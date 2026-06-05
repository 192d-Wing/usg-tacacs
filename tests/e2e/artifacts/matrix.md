# TACACS+ E2E Interoperability Matrix

| Scenario | usg-tacacs | tac_plus | Match |
|----------|:----------:|:--------:|:-----:|
| valid_auth | PASS | FAIL | NO |
| invalid_password | PASS | FAIL | NO |
| unknown_user | PASS | FAIL | NO |
| empty_credentials | PASS | FAIL | NO |
| long_credentials | PASS | FAIL | NO |
| secret_mismatch | PASS | PASS | YES |
| author_permit | PASS | FAIL | NO |
| author_deny | PASS | FAIL | NO |
| acct_start_stop | PASS | FAIL | NO |
| malformed_packet | PASS | PASS | YES |
| truncated_packet | PASS | PASS | YES |
| invalid_length | PASS | PASS | YES |
| concurrent_burst | PASS | FAIL | NO |

## Protocol Mismatches

### valid_auth

- **usg-tacacs**: status=1 (PASS)
- **tac_plus**: status=65 (UNKNOWN: 65)

### invalid_password

- **usg-tacacs**: status=2 (FAIL)
- **tac_plus**: status=38 (UNKNOWN: 38)

### unknown_user

- **usg-tacacs**: status=2 (FAIL)
- **tac_plus**: status=253 (UNKNOWN: 253)

### empty_credentials

- **usg-tacacs**: status=7 (ERROR)
- **tac_plus**: status=244 (UNKNOWN: 244)

### long_credentials

- **usg-tacacs**: status=2 (FAIL)
- **tac_plus**: status=161 (UNKNOWN: 161)

### author_permit

- **usg-tacacs**: status=2 (REPL)
- **tac_plus**: EXCEPTION: error: unpack requires a buffer of 88 bytes

### author_deny

- **usg-tacacs**: status=16 (FAIL)
- **tac_plus**: EXCEPTION: error: unpack requires a buffer of 224 bytes

### acct_start_stop

- **usg-tacacs**: start=2 stop=2
- **tac_plus**: start=50 stop=227

### concurrent_burst

- **usg-tacacs**: pass=20/20
- **tac_plus**: pass=0/20

