# Python Snippets

## Salt Module funtions

```python
def rotate_controller_tls_ticket_keys_by_id(
    controller_keycache_dir="/var/cache/salt/master/haproxy_tls_ticket_keys",
    region=None,
    tls_key=None,
    tls_key_id=None,
):
    """Rotate the controller tls key file content referenced by tls_key_id

    This function is used to update a file on the salt-controller that will
    provide the content for `pillar.certs.haproxy_tls_ticket_keys`

    The controller tls keys cache file is expected to be a specifict JSON format
    used to store the current tls ticket keys for tls_key_id being rotated.
    The files are region specific.

    Args:
        controller_keycache_dir (str): Directory path where the per-region controller
            keycache files are stored
        region (str): Region of the keyset to rotate
        tls_key_id (str): The tls-key id; matches a filepath
        tls_key (str, optional): 48 byte base64 encoded string to be used as
            the new ls ticket key in region; if missing one will be generated.

    Returns:
        dict: Example

            # pylint: disable=line-too-long
            {
              'name': tls_key_id,
              'changes': hap_response[0][1], # Text response from HAPEE
              'result': hap_response,        # Full response from HAPEE API, [('1', ['TLS ticket key updated!'])]
              'comment': "{tls_keys_path}: OK"
            }

    Raises:
        ArgumentValueError: if tls_key_id or region kwargs are missing|empty
        ArgumentValueError: if tls_key_id is not available in the keycache file
        FileNotFoundError: if the controller_keycache_dir or derived region file
            path is nonexistent
        JSONDecodeError: if the keycache file contains invalid JSON
    """
    if not region:
        raise ArgumentValueError(
            "region kwarg is required and cannot be an empty string."
        )

    if not tls_key_id:
        raise ArgumentValueError(
            "tls_key_id kwarg is required and cannot be an empty string."
        )

    if not tls_key:
        # No tls_key provided, generate one instead
        tls_key = base64.b64encode(secrets.token_bytes(48)).decode("utf-8")

    try:
        if len(base64.b64decode(tls_key, validate=True)) != 48:
            raise ArgumentValueError(
                "The tls_key kwarg is invalid, should be a 48 byte base64 encoded string."
            )
    except binascii.Error as exc:
        raise ArgumentValueError(
            f"The tls_key kwarg is invalid and will not decode: {exc}"
        ) from exc

    with open(
        controller_keycache_dir + "/" + region + ".json", "r+", encoding="utf-8"
    ) as keycache_file:
        keycache = json.load(keycache_file)

    keyset = keycache.get(tls_key_id, None)
    if keyset is None:
        raise ArgumentValueError(
            f"The tls_key_id {tls_key_id} is not available in the keycache."
        )

    # Does the metadata indicate the last rotation is longer than 12hr ago?
    if (
        datetime.datetime.utcnow()
        - datetime.datetime.fromtimestamp(keyset["last_rotation"])
    ) < datetime.timedelta(hours=12):
        return {
            "name": tls_key_id,
            "changes": "Failed to insert new TLS Key.",
            "result": False,
            "comment": f"Failure: {tls_key_id} is less than 12hr old.",
        }

    for key_rank, key in keyset.get("keys").items():
        try:
            if len(base64.b64decode(key, validate=True)) != 48:
                raise ValueError(
                    f"A key {key_rank} {key} found in the keycache file is invalid,"
                    " should be a 48 byte base64 encoded string."
                )
        except binascii.Error as exc:
            raise ArgumentValueError(
                "A key found in the keycache file is invalid and will not decode:"
                f" {exc}"
            ) from exc

    # Validation looks good, execute rotation
    keycache[tls_key_id]["last_rotation"] = datetime.datetime.utcnow().timestamp()
    keycache[tls_key_id]["keys"]["first"] = keyset["keys"]["second"]
    keycache[tls_key_id]["keys"]["second"] = keyset["keys"]["third"]
    keycache[tls_key_id]["keys"]["third"] = tls_key

    with open(
        controller_keycache_dir + "/" + region + ".json", "w", encoding="utf-8"
    ) as keycache_file:
        json.dump(keycache, keycache_file, indent=4)

    return {
        "name": tls_key_id,
        "changes": "Inserted new TLS Key expiring the oldest.",
        "result": True,
        "comment": "Success: {tls_key_id} rotated.",
    }

def get_runtime_tls_ticket_keys(profile=None):
    """Return all current configured tls-ticket-keys known to an haproxy instance.

    Args:
        profile (str or dict, optional): Configuration profile to use to
            connect to haproxy. Passed in to _get_haproxy_connection unchanged

    Returns:
        list: Example:
            [('1',
              ['# id (file)',
               '0 (/dev/shm/hapee_tls_ticket_keys_01.txt)',
               '1 (/dev/shm/hapee_tls_ticket_keys_02.txt)'])]

    """
    hap = _get_haproxy_connection(profile=profile)

    tls_ticket_key_ids = hap.command("show tls-keys")

    return tls_ticket_key_ids


def get_runtime_tls_ticket_keys_by_id(tls_key_id=None, profile=None):
    """Return the current runtime tls-ticket-keys for a specific tls-key id.

       # 0 is the tls_key_id
       0.0 is the former tls ticket key
       0.1 is the current tls ticket key
       0.2 is the next tls ticket key

    Args:
        tls_key_id (str): The tls-key id; matches a filepath
        profile (str or dict, optional): Configuration profile to use to
            connect to haproxy. Passed in to _get_haproxy_connection unchanged

    Returns:
        list: Example (Current tls_key_id):
            [('1',
             ['# id secret',
             '# 0 (/dev/shm/hapee_tls_ticket_keys.txt)',
             '0.0 evRS5RFnaFTW4MJB3ZvdSh+gzR4eB7sZRto7aHHqnT6lXp1sEEW2GD6tsSkBSPMY',
             '0.1 76axdy3WW/oMu1zxYFmFvAmU31UlgZoAGgUFVbpB9FvEkgGMyW44pmedHCgf/9wi',
             '0.2 2t5enGzRZk0XzqIogkHhUNeLi7UoMa0Gx1rUZiX2+OyS+sKnsUnFgrjYw2XSLDKJ'])]

              Example (Non-existent tls_key_id):
            [('1', ['show tls-keys' unable to locate referenced filename'])]

    Raises:
        ArgumentValueError: If no tls_key_id was provided.

    """
    if not tls_key_id:
        raise ArgumentValueError(
            "tls_key_id kwarg is required and cannot be an empty string."
        )

    hap = _get_haproxy_connection(profile=profile)

    tls_ticket_keys = hap.command(f"show tls-keys {tls_key_id}")

    return tls_ticket_keys


def get_filebased_tls_ticket_keys_by_id(tls_key_id=None):
    """Return the content of the file backing a specific tls-key id.

    Args:
        tls_key_id (str): The tls-key id; matches a filepath

    Returns:
        list: of lines from the file located at tls_key_id path

    Raises:
        FileNotFoundError: if the file at tls_key_id path is missing
        ValueError: if the file contents do not validate
    """
    with open(tls_key_id, encoding="utf-8") as fdesc:
        tls_keys = [l.rstrip() for l in fdesc]

    # tls-key files should have exactly 3 keys, if there are more than 3
    # only the last 3 in the list are used by HAProxy
    if len(tls_keys) != 3:
        raise ValueError(
            f"Invalid number of lines in {tls_key_id}, {len(keys)} lines should be 3"
        )

    # Ensure the keys decode into 48 bytes
    for key in tls_keys:
        try:
            if len(base64.b64decode(key, validate=True)) != 48:
                raise ValueError(
                    f"Key from {tls_key_id} is invalid,"
                    f" {len(base64.b64decode(key, validate=True))} bytes should be 48."
                )
        except binascii.Error as exc:
            raise ValueError(f"Key from {tls_key_id} is invalid, {exc}") from exc

    return tls_keys


def insert_runtime_tls_ticket_key_by_id(tls_key_id=None, tls_key=None, profile=None):
    """Insert one new TLS key into the runtime TLS ticket key set for a specific tls_key_id

    This function will insert a new key into the tls-key set identified by tls_key_id
    causing the oldest key to be forgotten.

    This function does NOT update the on-disk / start-up tls-keys.

    Additional info on HAProxy tls-key rotation:
      https://<sanitized documentation link was here>

    Args:
        tls_key_id (str): The tls-key id; matches a filepath
        tls_key (str, optional): The new tls-key to rotate in; 48 byte base64
            encoded string one might create with `openssl rand -base64 48`.
            If a key is not provided a key will be generated.
        profile (str or dict, optional): Configuration profile to use to
            connect to haproxy. Passed in to _get_haproxy_connection unchanged

    Returns:
        dict: Example

            # pylint: disable=line-too-long
            {
              'name': tls_key_id,
              'changes': hap_response[0][1], # Text response from HAPEE
              'result': hap_response,        # Full response from HAPEE API, [('1', ['TLS ticket key updated!'])]
              'comment': "Attempted to insert new runtime TLS Ticket key."
            }

    Raises:
        ArgumentValueError: If the supplied tls_key fails our validation

    """
    if not tls_key_id:
        raise ArgumentValueError(
            "tls_key_id kwarg is required and cannot be an empty string."
        )

    # Validate the TLS key
    if not tls_key:
        raise ArgumentValueError(
            "tls_key kwarg is required and cannot be an empty string."
        )

    try:
        if len(base64.b64decode(tls_key, validate=True)) != 48:
            raise ArgumentValueError(
                "tls_key kwarg should be a 48 byte base64 encoded string."
            )
    except binascii.Error as exc:
        raise ArgumentValueError(f"tls key kwarg is invalid, {exc}") from exc

    hap = _get_haproxy_connection(profile=profile)

    hap_response = hap.command(f"set ssl tls-key {tls_key_id} {tls_key}")

    response = {
        "name": tls_key_id,
        "changes": hap_response[0][1],
        "result": bool(hap_response[0][1] != "TLS ticket key updated!"),
        "comment": "Attempted to insert new runtime TLS Ticket key.",
    }

    return response
```

