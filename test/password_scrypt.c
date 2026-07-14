# include <kfun.h>


private int now_millis()
{
    mixed *now;

    now = millitime();
    return now[0] * 1000 + (int) (now[1] * 1000.0);
}

private string replace_byte(string value, int offset, int byte)
{
    value = value[..];
    value[offset] = byte;
    return value;
}

private int record_is_rejected(string encoded)
{
    return !password_hash_valid(encoded) &&
	   !password_verify("NativePasswordTest123!", encoded);
}

/*
 * exercise the native password API without returning records or passwords
 */
mapping run()
{
    string encoded, encoded2, maximum, modified;
    string err;
    int hashMillis, i, start, totalHash, verifyMillis, worstHash;

# if !defined(KF_PASSWORD_HASH) || !defined(KF_PASSWORD_VERIFY) || \
    !defined(KF_PASSWORD_HASH_VALID)
    error("Password kfun feature macros are missing");
# endif

    start = now_millis();
    encoded = password_hash("NativePasswordTest123!");
    hashMillis = now_millis() - start;
    if (strlen(encoded) != 119 || encoded[.. 21] !=
	"$EL2$scrypt$32768$8$1$" || !password_hash_valid(encoded)) {
	error("Generated record is invalid");
    }
    start = now_millis();
    if (!password_verify("NativePasswordTest123!", encoded)) {
	error("Correct password rejected");
    }
    verifyMillis = now_millis() - start;
    if (password_verify("DifferentNativePassword", encoded)) {
	error("Wrong password accepted");
    }
    encoded2 = password_hash("NativePasswordTest123!");
    if (encoded == encoded2) {
	error("Salt was reused");
    }
    modified = replace_byte(encoded, 22,
			    (encoded[22] == '0') ? '1' : '0');
    if (!password_hash_valid(modified) ||
	password_verify("NativePasswordTest123!", modified)) {
	error("Modified salt accepted");
    }
    modified = replace_byte(encoded, 55,
			    (encoded[55] == '0') ? '1' : '0');
    if (!password_hash_valid(modified) ||
	password_verify("NativePasswordTest123!", modified)) {
	error("Modified key accepted");
    }
    if (!record_is_rejected(replace_byte(encoded, 3, '9')) ||
	!record_is_rejected(replace_byte(encoded, 5, 'x')) ||
	!record_is_rejected(replace_byte(encoded, 12, '9')) ||
	!record_is_rejected(replace_byte(encoded, 18, '9')) ||
	!record_is_rejected(replace_byte(encoded, 20, '9')) ||
	!record_is_rejected(encoded[.. 117]) ||
	!record_is_rejected(encoded + "x") ||
	!record_is_rejected(replace_byte(encoded, 22, 'g')) ||
	!record_is_rejected(replace_byte(encoded, 55, 'g'))) {
	error("Malformed record accepted");
    }
    err = catch(password_hash(""));
    if (!err || password_verify("", encoded)) {
	error("Empty password behavior is incorrect");
    }
    maximum = "";
    for (i = 0; i < 128; i++) {
	maximum += "a";
    }
    modified = password_hash(maximum);
    if (!password_verify(maximum, modified)) {
	error("128-byte password rejected");
    }
    err = catch(password_hash(maximum + "a"));
    if (!err || password_verify(maximum + "a", modified)) {
	error("Over-limit password accepted");
    }
    worstHash = hashMillis;
    for (i = 0; i < 5; i++) {
	start = now_millis();
	modified = password_hash("RepeatedNativePasswordTest123!");
	start = now_millis() - start;
	totalHash += start;
	if (start > worstHash) {
	    worstHash = start;
	}
	if (!password_verify("RepeatedNativePasswordTest123!", modified)) {
	    error("Repeated hash failed");
	}
    }
    return ([
	"all_checks" : TRUE,
	"average_hash_millis" : totalHash / 5,
	"first_hash_millis" : hashMillis,
	"record_length" : strlen(encoded),
	"sequential_attempts" : 5,
	"verify_millis" : verifyMillis,
	"worst_hash_millis" : worstHash
    ]);
}
