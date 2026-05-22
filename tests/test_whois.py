"""
Tests para WhoisLookup
"""

from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, 'src')

from whois_lookup import WhoisLookup


@patch('whois_lookup.subprocess.run')
def test_whois_exitoso(mock_run):
    mock_proc = MagicMock()
    mock_proc.stdout = (
        "Domain Name: EXAMPLE.COM\n"
        "Registry Domain ID: 123\n"
        "Registrar: Example Registrar Inc\n"
        "Creation Date: 2000-01-01T00:00:00Z\n"
        "Registry Expiry Date: 2030-01-01T00:00:00Z\n"
        "Name Server: NS1.EXAMPLE.COM\n"
        "Name Server: NS2.EXAMPLE.COM\n"
        "Domain Status: clientDeleteProhibited\n"
    )
    mock_run.return_value = mock_proc

    w = WhoisLookup()
    res = w.consultar('example.com')

    assert res['dominio'] == 'example.com'
    assert res['registrar'] == 'Example Registrar Inc'
    assert res['creacion'] is not None
    assert res['expiracion'] is not None
    assert 'ns1.example.com' in [ns.lower() for ns in res['name_servers']]


@patch('whois_lookup.subprocess.run')
def test_whois_no_existe(mock_run):
    mock_proc = MagicMock()
    mock_proc.stdout = "No match for domain EXAMPLE.COM"
    mock_run.return_value = mock_proc

    w = WhoisLookup()
    res = w.consultar('noexiste.invalid')

    assert res['dominio'] == 'noexiste.invalid'
    assert res['registrar'] is None
