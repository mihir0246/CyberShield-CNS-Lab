import json
import pytest


def test_health_check_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "healthy"
    assert data["app"] == "CyberShield: Integrated Cryptography and Network Security Laboratory"
    assert "tools" in data


def test_dashboard_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"CYBERSHIELD" in response.data
    assert b"Syllabus Laboratory Experiments" in response.data


def test_caesar_api_endpoint(client):
    # Encrypt
    res_enc = client.post(
        "/ciphers/caesar/encrypt",
        json={"plaintext": "CyberShield Test", "shift": 4},
    )
    assert res_enc.status_code == 200
    data_enc = json.loads(res_enc.data)
    assert data_enc["success"] is True
    ciphertext = data_enc["data"]["ciphertext"]

    # Decrypt
    res_dec = client.post(
        "/ciphers/caesar/decrypt",
        json={"ciphertext": ciphertext, "shift": 4},
    )
    assert res_dec.status_code == 200
    data_dec = json.loads(res_dec.data)
    assert data_dec["success"] is True
    assert data_dec["data"]["plaintext"] == "CyberShield Test"


def test_hill_validate_key_endpoint(client):
    res = client.post(
        "/hill/validate_key",
        json={"key_matrix": [[3, 3], [2, 5]], "size": 2},
    )
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["success"] is True
    assert data["invertible"] is True
    assert data["determinant_mod26"] == 9


def test_rsa_api_endpoint(client):
    # Keygen
    res_gen = client.post("/rsa/generate_keys", json={"key_size": 1024})
    assert res_gen.status_code == 200
    data_gen = json.loads(res_gen.data)
    pub_pem = data_gen["public_key_pem"]
    priv_pem = data_gen["private_key_pem"]

    # Encrypt
    res_enc = client.post(
        "/rsa/encrypt",
        json={"plaintext": "Secret Payload", "public_key_pem": pub_pem},
    )
    assert res_enc.status_code == 200
    cipher_b64 = json.loads(res_enc.data)["data"]["ciphertext_b64"]

    # Decrypt
    res_dec = client.post(
        "/rsa/decrypt",
        json={"ciphertext": cipher_b64, "private_key_pem": priv_pem},
    )
    assert res_dec.status_code == 200
    assert json.loads(res_dec.data)["data"]["recovered_plaintext"] == "Secret Payload"


def test_404_error_page(client):
    response = client.get("/non_existent_cyber_route_404")
    assert response.status_code == 404
    assert b"404 - Page Not Found" in response.data
