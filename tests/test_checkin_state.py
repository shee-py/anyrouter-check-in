import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import checkin
from checkin import generate_balance_hash


def test_balance_hash_changes_when_quota_changes():
	before = {'account_1': {'quota': 100.0, 'used': 20.0}}
	after = {'account_1': {'quota': 125.0, 'used': 20.0}}

	assert generate_balance_hash(before) != generate_balance_hash(after)


def test_balance_hash_changes_when_used_quota_changes():
	before = {'account_1': {'quota': 100.0, 'used': 20.0}}
	after = {'account_1': {'quota': 100.0, 'used': 21.0}}

	assert generate_balance_hash(before) != generate_balance_hash(after)


def test_balance_hash_is_stable_for_equivalent_balances():
	left = {
		'account_2': {'quota': 50.0, 'used': 1.0},
		'account_1': {'quota': 100.0, 'used': 20.0},
	}
	right = {
		'account_1': {'used': 20.0, 'quota': 100.0},
		'account_2': {'used': 1.0, 'quota': 50.0},
	}

	assert generate_balance_hash(left) == generate_balance_hash(right)


def test_balance_state_round_trip(tmp_path, monkeypatch):
	state_file = tmp_path / 'balance_state.json'
	monkeypatch.setattr(checkin, 'BALANCE_STATE_FILE', str(state_file))
	balances = {
		'account_1': {'quota': 202.67, 'used': 22.33},
		'account_2': {'quota': 150.0, 'used': 0.0},
	}

	checkin.save_balance_state(balances)

	assert checkin.load_balance_state() == balances


def test_balance_state_invalid_json_returns_empty(tmp_path, monkeypatch):
	state_file = tmp_path / 'balance_state.json'
	state_file.write_text('{invalid', encoding='utf-8')
	monkeypatch.setattr(checkin, 'BALANCE_STATE_FILE', str(state_file))

	assert checkin.load_balance_state() == {}
