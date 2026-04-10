import base64
import hashlib
import json
import random
from datetime import datetime
from urllib.parse import parse_qsl, quote

from Cryptodome.Cipher import AES
from yarl import URL

from crawlers._utils import new_http_client, SeriesDirectory, tqdme, pkcs7_unpad, suggest_save_dir

# Same as frontend dWithout / forge.util.decode64(keyB64): looks like hex but is Base64 key material.
_CONFIG_KEY_B64 = "c57b1589172b85531c2dbad73c5e9056"


def _decrypt_get_configs_body(enc_b64: str) -> str:
	"""Decrypt /film/api/m/config/getConfigs body: Base64(nonce12 || ciphertext || tag16), AES-GCM."""
	key = base64.b64decode(_CONFIG_KEY_B64.encode("ascii"))
	raw = base64.b64decode(enc_b64.strip().encode("ascii"))
	nonce, rest = raw[:12], raw[12:]
	tag, ciphertext = rest[-16:], rest[:-16]
	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def _axios_interceptor_cetus_params():
	"""
	cetusDecryptAes uses cipherSecretKey / cipherIv from getTWoParams(), not cetusAESKey from getConfigs.
	If the site re-obfuscates, search getTWoParams in /film/assets/index-*.js and update the arrays below.
	"""
	key_arr = [54, 56, 98, 57, 100, 98, 100, 57, 49, 102, 53, 99, 51, 57, 54, 48, 57, 57, 100, 51, 49, 101, 100, 57, 51, 98, 56, 53, 48, 55, 97, 99]
	s1 = [j ^ (q % 7) for q, j in enumerate(key_arr)]
	s2 = [j ^ (q % 7) for q, j in enumerate(s1)]
	cipher_secret_key = "".join(chr(x) for x in s2)

	iv_arr = [100, 51, 57, 100, 102, 99, 51, 48, 100, 53, 52, 56, 98, 56, 52, 49]
	v1 = [j ^ (q % 5) for q, j in enumerate(iv_arr)]
	v2 = [j ^ (q % 5) for q, j in enumerate(v1)]
	cipher_iv = "".join(chr(x) for x in v2)
	return {"cipherSecretKey": cipher_secret_key, "cipherIv": cipher_iv}


def _cetus_decrypt_aes(cetus: dict, input_: str):
	# Match frontend: Utf8.parse(cipherSecretKey); IV is UTF-8 of hex digit string (16 bytes), same as browser.
	key = cetus["cipherSecretKey"].encode("utf-8")
	iv = cetus["cipherIv"].encode("utf-8")
	input_ = base64.b64decode(input_.encode())

	cipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted = cipher.decrypt(input_)
	return pkcs7_unpad(decrypted).decode("utf-8")


def _call_image_service(client, token, params):
	params["randnum"] = random.uniform(0, 1)
	return client.get(
		"/vna/image/Home/ImageService",
		params=params,
		headers={"Authorization": token}
	)


async def _try_enrich_study_via_common_study(client, film_token: str, study: dict, cetus: dict) -> dict:
	"""
	Browser uses GetStudyByAccessionNo (/film/api/m/common/study) when loading by accession.
	Share payloads may omit studyInstanceUid; this endpoint can fill it (still empty if hospital sends nothing).
	"""
	if (study.get("studyInstanceUid") or "").strip():
		return study
	params = {
		"accessionNo": study["accessionNo"],
		"locationCode": study["orgCode"],
		"orgCode": study["orgCode"],
	}
	# This hospital returns 440 if Authorization is plaintext ThirdPartBearer; keep ciphertext from share API.
	async with client.get(
		"/film/api/m/common/study",
		params=params,
		headers={"Authorization": film_token},
	) as response:
		payload = await response.json()
	if payload.get("code") != "U000000":
		return study
	enc = (payload.get("data") or {}).get("encryptPatientStudy")
	if not enc:
		return study
	try:
		rows = json.loads(_cetus_decrypt_aes(cetus, enc)).get("records") or []
	except Exception:
		return study
	if not rows:
		return study
	row = rows[0]
	suid = (row.get("studyInstanceUid") or "").strip()
	if not suid:
		return study
	merged = dict(study)
	merged["studyInstanceUid"] = suid
	if row.get("uniqueId") or row.get("accessionUniqueId"):
		merged["uniqueId"] = row.get("uniqueId") or row["accessionUniqueId"]
	return merged


_MISSING_UID_MSG = (
	"No Study UID in share or /m/common/study, and /m/report/getHierachy did not return an image hierarchy; "
	"cannot download DICOM."
)

# Return value of makeParams() in /film/assets/index-*.js; resync after major site updates.
_FILM_REQUEST_SIGN_SALT = "23599a8ad8db0d1e51310376b92843f56d25a41193c3a7870e32df3446ad4700"


def _decrypt_film_app_token(encrypted_token: str) -> str:
	"""Share API token / uapToken is dWithout ciphertext; same algorithm as getConfigs."""
	return _decrypt_get_configs_body(encrypted_token)


def _film_signed_headers_get(app_token_clear: str, params_for_sign: dict) -> dict:
	"""
	Anti-tamper headers axios adds for most /film/api requests (forge.sha256).
	Key order in params_for_sign must match the actual query parameter order.
	"""
	q = {}
	for key, val in params_for_sign.items():
		if val is None:
			continue
		if isinstance(val, bool):
			val = "true" if val else "false"
		elif isinstance(val, int):
			val = str(val)
		elif isinstance(val, float):
			val = str(val)
		if val == "":
			continue
		q[key] = val
	x_request = str(random.randrange(0, 100_000_000))
	x_list = ",".join(q.keys())
	payload = json.dumps(q, separators=(",", ":"), ensure_ascii=False)
	enc = quote(payload, safe="")
	digest = hashlib.sha256(
		(app_token_clear + _FILM_REQUEST_SIGN_SALT + enc + x_request).encode("utf-8")
	).hexdigest()
	return {
		"Authorization": app_token_clear,
		"X-Request": x_request,
		"X-List": x_list,
		"X-Source": digest,
	}


def _film_hierachy_query_params(study: dict) -> dict:
	"""Same object as `ae` in getImageHierachy (patient flow often adds source=CloudFilm)."""
	return {
		"imageType": study.get("procedureOfficeCode") or "RAD",
		"locationCode": study["orgCode"],
		"accessionNo": study["accessionNo"],
		"source": "CloudFilm",
	}


async def _series_list_via_signed_film_hierachy(client, app_token_clear: str, study: dict):
	"""Fetch hierarchy by accession via /m/report/getHierachy (browser parity). Returns (series_list, info_patch)."""
	params = _film_hierachy_query_params(study)
	headers = _film_signed_headers_get(app_token_clear, params)
	async with client.get("/film/api/m/report/getHierachy", params=params, headers=headers) as response:
		payload = await response.json()
	if payload.get("code") != "U000000" or not payload.get("data"):
		params = {k: v for k, v in params.items() if k != "source"}
		params["appendTags"] = "PI-film-include"
		headers = _film_signed_headers_get(app_token_clear, params)
		async with client.get("/film/api/m/report/getHierachy", params=params, headers=headers) as response:
			payload = await response.json()
		if payload.get("code") != "U000000" or not payload.get("data"):
			raise RuntimeError(_MISSING_UID_MSG)
	tree = json.loads(payload["data"])
	st0 = tree["PatientInfo"]["StudyList"][0]
	suid = (st0.get("UID") or "").strip()
	if not suid:
		raise RuntimeError(_MISSING_UID_MSG)
	info_patch = {
		"studyInstanceUid": suid,
		"uniqueId": st0.get("UniqueID") or study.get("accessionUniqueId"),
		"orgCode": st0.get("LocationCode") or study["orgCode"],
	}
	return st0["SeriesList"], info_patch


async def run(share_url):
	code = dict(parse_qsl(share_url[share_url.rfind("?") + 1:]))["code"]
	origin = str(URL(share_url).origin())

	async with new_http_client(origin, headers={"Referer": origin}) as client:

		async with client.get("/film/api/m/config/getConfigs") as response:
			raw = await response.text()
			# Warm session/WAF like the SPA; share payload uses getTWoParams, not cetusAESKey from config.
			json.loads(_decrypt_get_configs_body(raw))

		cetus_for_share = _axios_interceptor_cetus_params()

		async with client.post("/film/api/m/doctor/getStudyByShareCodeWithToken", json={"code": code}) as response:
			body = await response.json()
			if body["code"] != "U000000":
				raise Exception(body["data"])

			data = _cetus_decrypt_aes(cetus_for_share, body["data"]["encryptionStudyInfo"])
			study = json.loads(data)["records"][0]
			study = await _try_enrich_study_via_common_study(client, body["data"]["token"], study, cetus_for_share)
			app_token_clear = _decrypt_film_app_token(body["data"]["token"])

			save_to = suggest_save_dir(
				study["patientName"],
				study["procedureItemName"],
				str(datetime.fromtimestamp(study["studyDatetime"] / 1000))
			)
			print(f"Saving to: {save_to}")
			if study.get("studyLevelList"):
				info = dict(study["studyLevelList"][0])
			else:
				info = {
					"studyInstanceUid": study.get("studyInstanceUid") or "",
					"uniqueId": study.get("uniqueId") or study.get("accessionUniqueId"),
					"orgCode": study["orgCode"],
				}

		async with client.get("/viewer/2d/Dapeng/Viewer/GetCredentialsToken") as response:
			body = await response.json()
			body = json.loads(body["result"])
			credentials_token = "Bearer " + body["access_token"]

		suid = (info.get("studyInstanceUid") or info.get("studyInstanceUId") or "").strip()
		if suid:
			params = {
				"CommandType": "GetHierachy",
				"StudyUID": suid,
				"UniqueID": info["uniqueId"],
				"LocationCode": info["orgCode"],
				"UserId": "UIH",
				"appendTags": "PI-film-include",
				"includeDeleted": "false",
			}
			async with _call_image_service(client, credentials_token, params) as response:
				body = await response.json()
				series_list = body["PatientInfo"]["StudyList"][0]["SeriesList"]
		else:
			series_list, patch = await _series_list_via_signed_film_hierachy(client, app_token_clear, study)
			info.update(patch)

		suid = (info.get("studyInstanceUid") or "").strip()

		for series in series_list:
			desc, number, slices = series["SeriesDes"], series["SeriesNum"], series["ImageList"]
			dir_ = SeriesDirectory(save_to, number, desc, len(slices))

			for i, image in tqdme(slices, desc=desc):
				params = {
					"CommandType": "GetImage",
					"ContentType": "application/dicom",
					"ObjectUID": image["UID"],
					"StudyUID": suid,
					"SeriesUID": series["UID"],
					"includeDeleted": "false",
				}
				async with _call_image_service(client, credentials_token, params) as response:
					dir_.get(i, "dcm").write_bytes(await response.read())
