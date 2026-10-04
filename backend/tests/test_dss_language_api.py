from backend.tests.test_api_execution import create_execution


def test_dss_evidence_reads_require_identity_and_existing_execution(client,viewer_headers,operator_headers):
    execution_id=create_execution(client,operator_headers,"integration")
    path=f"/api/v1/executions/{execution_id}/dss-language-evidence"
    assert client.get(path).status_code==401
    response=client.get(path,headers=viewer_headers)
    assert response.status_code==200,response.text
    assert response.json()["items"]==[] and response.json()["execution_id"]==execution_id
    assert client.get("/api/v1/executions/missing/dss-language-evidence",headers=viewer_headers).status_code==404
    assert client.get(path+"?subject=case:any",headers=viewer_headers).status_code==422
    unavailable=client.get(f"/api/v1/executions/{execution_id}/dss-driver-evidence?epoch=known",headers=viewer_headers)
    assert unavailable.status_code==409 and "unavailable" in unavailable.text


def test_dss_packet_evidence_digest_selector_is_bounded(client,viewer_headers,operator_headers):
    execution_id=create_execution(client,operator_headers,"integration")
    path=f"/api/v1/executions/{execution_id}/dss-driver-evidence?epoch=known&packet_sha256="
    for bad in ("../secret","f"*65,"NOT-A-HASH"):
        assert client.get(path+bad,headers=viewer_headers).status_code==422
