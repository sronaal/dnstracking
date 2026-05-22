"""
Tests para DNSResolver
"""

from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, 'src')

from resolver import DNSResolver


@patch('resolver.dns.resolver.Resolver')
def test_resolver_registro_exitoso(mock_resolver):
    mock_instance = MagicMock()
    mock_resolver.return_value = mock_instance

    mock_answer = MagicMock()
    mock_rdata = MagicMock()
    mock_rdata.__str__ = lambda self: '93.184.216.34'
    mock_answer.__iter__ = lambda self: iter([mock_rdata])
    mock_instance.resolve.return_value = mock_answer

    r = DNSResolver()
    resultado = r.resolver_registro('example.com', 'A')
    assert resultado == ['93.184.216.34']


@patch('resolver.dns.resolver.Resolver')
def test_resolver_registro_nxdomain(mock_resolver):
    import dns.resolver
    mock_instance = MagicMock()
    mock_resolver.return_value = mock_instance
    mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN

    r = DNSResolver()
    resultado = r.resolver_registro('noexiste.example.com', 'A')
    assert resultado == []


@patch('resolver.dns.resolver.Resolver')
def test_es_dominio_valido(mock_resolver):
    mock_instance = MagicMock()
    mock_resolver.return_value = mock_instance

    r = DNSResolver()
    assert r.es_dominio_valido('example.com') is True


@patch('resolver.dns.resolver.Resolver')
def test_es_dominio_invalido(mock_resolver):
    import dns.resolver
    mock_instance = MagicMock()
    mock_resolver.return_value = mock_instance
    mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN

    r = DNSResolver()
    assert r.es_dominio_valido('noexiste.invalid') is False


@patch('resolver.dns.resolver.Resolver')
def test_enumerar_basicos(mock_resolver):
    mock_instance = MagicMock()
    mock_resolver.return_value = mock_instance

    mock_answer = MagicMock()
    mock_rdata = MagicMock()
    mock_rdata.__str__ = lambda self: '93.184.216.34'
    mock_answer.__iter__ = lambda self: iter([mock_rdata])
    mock_instance.resolve.return_value = mock_answer

    r = DNSResolver()
    basicos = r.enumerar_basicos('example.com')
    assert 'A' in basicos
    assert 'AAAA' in basicos
    assert 'MX' in basicos
