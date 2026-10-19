import json
import pytest
from jscope.security_transport import PolicyError, TransportPolicy, GuardedSession, validate_url, normalize_host
from jscope.passive_discovery import discover_candidates, persist_candidates, approve_hosts

def test_hostname_boundary_and_normalization():
    hosts={'Example.COM.'}
    assert validate_url('https://API.example.com./x',hosts)=='https://api.example.com/x'
    assert normalize_host('BÜCHER.example')=='xn--bcher-kva.example'
    with pytest.raises(PolicyError): validate_url('https://example.com.attacker.test/',hosts)
    with pytest.raises(PolicyError): validate_url('https://attacker.test/',hosts)

def test_url_tricks_and_ports():
    hosts={'example.com'}
    for url in ['https://user@example.com/','https://example.com:0/','ftp://example.com/','https://example.com:99999/']:
        with pytest.raises(PolicyError): validate_url(url,hosts)

def test_ip_literal_and_ipv6():
    assert validate_url('http://127.0.0.1/',{'127.0.0.1'})=='http://127.0.0.1/'
    assert validate_url('https://[2001:db8::1]/',{'2001:db8::1'})=='https://[2001:db8::1]/'

def test_transport_blocks_before_request(monkeypatch):
    class Dummy:
        def __init__(self): self.called=False; self.verify=True
        def request(self,*a,**kw): self.called=True; raise AssertionError('must not send')
    d=Dummy(); p=TransportPolicy({'example.com'},'assessment-test',allow_private=True)
    s=GuardedSession(p,d)
    with pytest.raises(PolicyError): s.get('https://example.com.attacker.test/')
    assert not d.called

def test_discovery_dedup_and_no_approval(tmp_path):
    hosts=tmp_path/'hosts.txt'; hosts.write_text('api.example.com\napi.example.com\nother.test\nBAD HOST\n')
    c=discover_candidates('example.com',[hosts])
    assert len([x for x in c if x.get('hostname')=='api.example.com'])==1
    assert any(x['state']=='excluded' and x['reason']=='outside-root-domain' for x in c)
    assert all(x['state']!='approved' for x in c)

def test_approval_is_assessment_specific_and_requires_known(tmp_path):
    p=tmp_path/'assessment.json'
    data={'schema':'jscope-assessment/1','assessment_id':'A1','root_domain':'example.com','hosts':{'example.com':{'state':'known'},'api.example.com':{'state':'known'}},'authorization':{'approved_hosts':[]}}
    p.write_text(json.dumps(data))
    approve_hosts(p,['api.example.com'])
    got=json.loads(p.read_text()); assert got['authorization']['approved_hosts']==['api.example.com']
    assert got['approval_history'][0]['assessment_id']=='A1'
    with pytest.raises(Exception): approve_hosts(p,['missing.example.com'])

def test_corrupt_manifest_fails_closed(tmp_path):
    p=tmp_path/'bad.json'; p.write_text('{')
    with pytest.raises(Exception): persist_candidates(p,[])

def test_transport_requires_exact_approved_host_not_implicit_subdomain(monkeypatch):
    class Dummy:
        verify=True
        called=False
        def request(self,*a,**kw): self.called=True; raise AssertionError('must not send')
    d=Dummy(); p=TransportPolicy({'example.com'},'A2',allow_private=True)
    monkeypatch.setattr(p,'check_dns',lambda url: None)
    s=GuardedSession(p,d)
    with pytest.raises(PolicyError): s.get('https://api.example.com/')
    assert not d.called

def test_redirect_destination_validated_before_following(monkeypatch):
    class Response:
        status_code=302; headers={'Location':'https://outside.test/private'}; content=b''
        is_redirect=True; is_permanent_redirect=False
        def close(self): pass
    class Dummy:
        verify=True
        def __init__(self): self.calls=0
        def request(self,*a,**kw): self.calls+=1; return Response()
    d=Dummy(); p=TransportPolicy({'example.com'},'A3',allow_private=True)
    monkeypatch.setattr(p,'check_dns',lambda url: None)
    with pytest.raises(PolicyError): GuardedSession(p,d).get('https://example.com/start')
    assert d.calls==1
