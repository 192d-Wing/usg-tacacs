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
- **tac_plus**: status=98 (UNKNOWN: 98)

### invalid_password

- **usg-tacacs**: status=2 (FAIL)
- **tac_plus**: status=163 (UNKNOWN: 163)

### unknown_user

- **usg-tacacs**: status=2 (FAIL)
- **tac_plus**: status=173 (UNKNOWN: 173)

### empty_credentials

- **usg-tacacs**: status=7 (ERROR)
- **tac_plus**: status=248 (UNKNOWN: 248)

### long_credentials

- **usg-tacacs**: status=2 (FAIL)
- **tac_plus**: status=102 (UNKNOWN: 102)

### author_permit

- **usg-tacacs**: status=17 (ERROR)
- **tac_plus**: EXCEPTION: error: unpack requires a buffer of 127 bytes

### author_deny

- **usg-tacacs**: status=17 (ERROR)
- **tac_plus**: EXCEPTION: error: unpack requires a buffer of 93 bytes

### acct_start_stop

- **usg-tacacs**: start=2 stop=2
- **tac_plus**: start=198 stop=251

### concurrent_burst

- **usg-tacacs**: pass=20/20
- **tac_plus**: pass=0/20

