import json
from unittest.mock import MagicMock, patch

import pytest

from checkin import check_in_account, run_check_in_requests
from utils.config import AccountConfig, AppConfig, load_accounts_config


def test_account_config_access_token_parsing():
	"""测试 AccountConfig 解析 access_token 及 has_access_token() 方法"""
	data = {
		'name': 'AgentRouter Token Account',
		'provider': 'agentrouter',
		'access_token': 'sk-test-token-123456',
		'api_user': '12345',
	}
	config = AccountConfig.from_dict(data, 0)
	assert config.name == 'AgentRouter Token Account'
	assert config.provider == 'agentrouter'
	assert config.access_token == 'sk-test-token-123456'
	assert config.api_user == '12345'
	assert config.has_access_token() is True
	assert config.has_login_credentials() is False


def test_load_accounts_config_with_access_token(monkeypatch, capsys):
	"""测试 load_accounts_config 允许 access_token + api_user 配置"""
	accounts_json = json.dumps(
		[
			{
				'name': 'Valid Token Account',
				'provider': 'agentrouter',
				'access_token': 'sk-secret-token-abcdef',
				'api_user': '67890',
			}
		]
	)
	monkeypatch.setenv('ANYROUTER_ACCOUNTS', accounts_json)

	accounts = load_accounts_config()
	assert accounts is not None
	assert len(accounts) == 1
	assert accounts[0].access_token == 'sk-secret-token-abcdef'
	assert accounts[0].api_user == '67890'

	captured = capsys.readouterr()
	# 确保敏感 token 未打入标准输出
	assert 'sk-secret-token-abcdef' not in captured.out
	assert 'sk-secret-token-abcdef' not in captured.err


def test_load_accounts_config_access_token_missing_api_user(monkeypatch, capsys):
	"""测试 access_token 配置但缺失 api_user 时给出安全错误提示且不泄露 token"""
	secret_token = 'sk-secret-token-to-hide-123'
	accounts_json = json.dumps(
		[
			{
				'name': 'Invalid Token Account',
				'provider': 'agentrouter',
				'access_token': secret_token,
			}
		]
	)
	monkeypatch.setenv('ANYROUTER_ACCOUNTS', accounts_json)

	accounts = load_accounts_config()
	assert accounts is None

	captured = capsys.readouterr()
	assert 'missing required field (api_user)' in captured.out
	# 确保不泄露真实或测试 token
	assert secret_token not in captured.out
	assert secret_token not in captured.err


def test_auth_priority_email_over_access_token():
	"""测试优先级: email/password > access_token > cookies"""
	data = {
		'name': 'Priority Account',
		'email': 'user@example.com',
		'password': 'pass123',
		'access_token': 'sk-token',
		'cookies': {'session': 'sess'},
		'api_user': '123',
	}
	config = AccountConfig.from_dict(data, 0)
	assert config.has_login_credentials() is True
	assert config.has_access_token() is True


def test_run_check_in_requests_injects_authorization_header(monkeypatch, capsys):
	"""测试 run_check_in_requests 注入 Authorization: Bearer <token> 且不打印 token"""
	account = AccountConfig(
		name='Token Test',
		provider='agentrouter',
		access_token='my-secret-token-xyz',
		api_user='12345',
	)
	app_config = AppConfig.load_from_env()
	provider_config = app_config.get_provider('agentrouter')

	sent_headers = {}

	def mock_get(url, headers=None, timeout=None):
		nonlocal sent_headers
		sent_headers = headers or {}
		mock_resp = MagicMock()
		mock_resp.status_code = 200
		mock_resp.json.return_value = {
			'success': True,
			'data': {'quota': 1000000, 'used_quota': 500000},
		}
		return mock_resp

	with patch('httpx.Client.get', side_effect=mock_get):
		success, before, after = run_check_in_requests(
			all_cookies={},
			account=account,
			account_name='Token Test',
			provider_config=provider_config,
			access_token=account.access_token,
			use_proxy=False,
		)

	assert success is True
	assert sent_headers.get('Authorization') == 'Bearer my-secret-token-xyz'
	assert sent_headers.get('new-api-user') == '12345'
	assert before['quota'] == 2.0  # 1,000,000 / 500,000
	assert before['used_quota'] == 1.0  # 500,000 / 500,000

	captured = capsys.readouterr()
	assert 'my-secret-token-xyz' not in captured.out
	assert 'my-secret-token-xyz' not in captured.err


@pytest.mark.asyncio
async def test_agentrouter_token_account_does_not_launch_browser(capsys):
	"""测试 AgentRouter access_token 账号分支不启动浏览器并完成自动签到"""
	account = AccountConfig(
		name='AgentRouter Token',
		provider='agentrouter',
		access_token='secret-token-abc',
		api_user='99999',
	)
	app_config = AppConfig.load_from_env()

	with (
		patch('checkin.launch_async') as mock_launch,
		patch('checkin.login_with_credentials') as mock_login,
		patch('checkin.get_waf_cookies_with_browser') as mock_waf,
		patch('httpx.Client.get') as mock_get,
	):
		mock_resp = MagicMock()
		mock_resp.status_code = 200
		mock_resp.json.return_value = {
			'success': True,
			'data': {'quota': 5000000, 'used_quota': 1000000},
		}
		mock_get.return_value = mock_resp

		success, before, after = await check_in_account(account, 0, app_config)

		assert success is True
		# 验证未调用任何浏览器相关函数
		mock_launch.assert_not_called()
		mock_login.assert_not_called()
		mock_waf.assert_not_called()

		# 验证正确换算 quota (5000000 / 500000 = 10.0, 1000000 / 500000 = 2.0)
		assert after['quota'] == 10.0
		assert after['used_quota'] == 2.0

	captured = capsys.readouterr()
	assert 'secret-token-abc' not in captured.out


def test_load_accounts_config_appends_agentrouter_env_vars(monkeypatch, capsys):
	"""测试当 ANYROUTER_ACCOUNTS 与 AgentRouter 环境变量同时存在时追加 AgentRouter 账号"""
	accounts_json = json.dumps(
		[
			{
				'name': 'Existing Account',
				'email': 'existing@example.com',
				'password': 'pass',
				'api_user': '111',
			}
		]
	)
	monkeypatch.setenv('ANYROUTER_ACCOUNTS', accounts_json)
	secret_token = 'sk-appended-agentrouter-token'
	monkeypatch.setenv('AGENTROUTER_ACCESS_TOKEN', secret_token)
	monkeypatch.setenv('AGENTROUTER_API_USER', '222')

	accounts = load_accounts_config()
	assert accounts is not None
	assert len(accounts) == 2
	assert accounts[0].name == 'Existing Account'
	assert accounts[1].name == 'AgentRouter'
	assert accounts[1].provider == 'agentrouter'
	assert accounts[1].access_token == secret_token
	assert accounts[1].api_user == '222'

	captured = capsys.readouterr()
	assert secret_token not in captured.out
	assert secret_token not in captured.err


def test_load_accounts_config_agentrouter_missing_api_user(monkeypatch, capsys):
	"""测试 AGENTROUTER_ACCESS_TOKEN 存在但缺 AGENTROUTER_API_USER 时报错并返回 None"""
	secret_token = 'sk-token-without-user'
	monkeypatch.setenv('AGENTROUTER_ACCESS_TOKEN', secret_token)
	monkeypatch.delenv('AGENTROUTER_API_USER', raising=False)

	accounts = load_accounts_config()
	assert accounts is None

	captured = capsys.readouterr()
	assert 'missing required field (AGENTROUTER_API_USER)' in captured.out
	assert secret_token not in captured.out
	assert secret_token not in captured.err


def test_load_accounts_config_only_agentrouter_env_vars(monkeypatch, capsys):
	"""测试无 ANYROUTER_ACCOUNTS 时仅凭借 AgentRouter 环境变量加载账号"""
	monkeypatch.delenv('ANYROUTER_ACCOUNTS', raising=False)
	secret_token = 'sk-only-agentrouter-token'
	monkeypatch.setenv('AGENTROUTER_ACCESS_TOKEN', secret_token)
	monkeypatch.setenv('AGENTROUTER_API_USER', '333')

	accounts = load_accounts_config()
	assert accounts is not None
	assert len(accounts) == 1
	assert accounts[0].name == 'AgentRouter'
	assert accounts[0].provider == 'agentrouter'
	assert accounts[0].access_token == secret_token
	assert accounts[0].api_user == '333'

	captured = capsys.readouterr()
	assert secret_token not in captured.out
	assert secret_token not in captured.err

