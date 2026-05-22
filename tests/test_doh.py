"""
Tests para DohResolver
"""

from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, 'src')

from doh_resolver import DohResolver


@patch('doh_resolver.requests.get')
def test_resolver_exitoso(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'Status': 0,
        'Answer': [
            {'type': 1, 'data': '93.184.216.34'},
        ],
    }
    mock_get.return_value = mock_resp

    d = DohResolver()
    res = d.resolver('example.com', 'A')

    assert res == ['93.184.216.34']
    mock_get.assert_called_once()


@patch('doh_resolver.requests.get')
def test_resolver_sin_resultados(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'Status': 0,
        'Answer': [],
    }
    mock_get.return_value = mock_resp

    d = DohResolver()
    res = d.resolver('noexiste.invalid', 'AAAA')

    assert res == []


@patch('doh_resolver.requests.get')
def test_enumerar_basicos(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'Status': 0,
        'Answer': [
            {'type': 1, 'data': '93.184.216.34'},
        ],
    }
    mock_get.return_value = mock_resp

    d = DohResolver()
    basicos = d.enumerar_basicos('example.com')

    assert 'A' in basicos
    assert basicos['A'] == ['93.184.216.34']


@patch('doh_resolver.requests.get')
def test_proveedor_invalido(mock_get):
    try:
        DohResolver(proveedor='invalido')
        assert False, "Debio lanzar ValueError"
    except ValueError:
        assert True
