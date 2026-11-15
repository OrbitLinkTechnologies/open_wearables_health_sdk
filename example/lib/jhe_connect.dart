import 'dart:convert';

import 'package:http/http.dart' as http;

// ────────────────────────────────────────────────────
// JHE invitation flow (OrbitLink fork)
//
// JHE invitation link:  https://<jhe-host>/clients/ow/launch?code=<jhe-host>_<token>
// Steps: redeem the invitation on JHE -> exchange the grant for a JHE access
// token (PKCE) -> ask JHE to create the Open Wearables user and mint SDK
// tokens -> sign in to the OW SDK with those tokens.
// ────────────────────────────────────────────────────

class JheInvite {
  final String host;
  final String token;
  JheInvite(this.host, this.token);
}

class JheConnection {
  final String owApiUrl;
  final String owUserId;
  final String accessToken;
  final String refreshToken;
  JheConnection(this.owApiUrl, this.owUserId, this.accessToken, this.refreshToken);
}

/// Accepts a pasted JHE link (...?code=host_token) or the bare host_token code.
/// Returns null when the input does not look like a JHE invitation, so the
/// original Open Wearables invitation-code path can handle it instead.
JheInvite? parseJheInvitation(String input) {
  var code = input.trim();
  if (code.isEmpty) return null;
  if (code.startsWith('http')) {
    code = Uri.tryParse(code)?.queryParameters['code'] ?? '';
  }
  final i = code.lastIndexOf('_');
  if (i <= 0) return null;
  final host = Uri.decodeComponent(code.substring(0, i));
  final token = code.substring(i + 1);
  if (!RegExp(r'^[A-Za-z0-9]{32}$').hasMatch(token) || !host.contains('.')) return null;
  return JheInvite(host, token);
}

// JHE may answer in snake_case or camelCase, so accept both.
dynamic _pick(Map<String, dynamic>? m, List<String> keys) {
  if (m == null) return null;
  for (final k in keys) {
    if (m[k] != null) return m[k];
  }
  return null;
}

Future<JheConnection> connectViaJhe(JheInvite invite, {void Function(String)? onStatus}) async {
  final base = 'https://${invite.host}';

  onStatus?.call('Redeeming invitation...');
  final redeem = await http.post(
    Uri.parse('$base/api/v1/invitation/${invite.token}'),
    headers: {'Cache-Control': 'no-cache'},
  );
  if (redeem.statusCode != 200) {
    throw Exception('Invitation rejected (${redeem.statusCode}): ${redeem.body}');
  }
  final body = jsonDecode(redeem.body) as Map<String, dynamic>;
  final grant = _pick(body, ['grant']) as Map<String, dynamic>?;
  final clientId = _pick(grant, ['client_id', 'clientId']);
  final code = _pick(grant, ['code']);
  final redirectUri = _pick(grant, ['redirect_uri', 'redirectUri']);
  if (clientId == null || code == null || redirectUri == null) {
    throw Exception('Unexpected invitation response, keys: ${grant?.keys.toList() ?? body.keys.toList()}');
  }
  var tokenEndpoint = (_pick(body, ['token_endpoint', 'tokenEndpoint']) ?? '$base/o/token/') as String;
  // JHE sits behind a proxy; make sure the token call goes over https.
  if (tokenEndpoint.startsWith('http://')) {
    tokenEndpoint = tokenEndpoint.replaceFirst('http://', 'https://');
  }

  onStatus?.call('Getting access token...');
  // PKCE verifier: the invitation token, plain base64, padding removed.
  final verifier = base64.encode(utf8.encode(invite.token)).replaceAll('=', '');
  final tokenResp = await http.post(
    Uri.parse(tokenEndpoint),
    body: {
      'code': code as String,
      'grant_type': 'authorization_code',
      'redirect_uri': redirectUri as String,
      'client_id': clientId as String,
      'code_verifier': verifier,
    },
  );
  if (tokenResp.statusCode != 200) {
    throw Exception('Token exchange failed (${tokenResp.statusCode}): ${tokenResp.body}');
  }
  final jheToken = (jsonDecode(tokenResp.body) as Map<String, dynamic>)['access_token'] as String?;
  if (jheToken == null) throw Exception('No access token from JHE');

  onStatus?.call('Creating Open Wearables user...');
  final owResp = await http.post(
    Uri.parse('$base/api/v1/ow/users'),
    headers: {
      'Authorization': 'Bearer $jheToken',
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache',
    },
    body: jsonEncode({'include_ow_tokens': true}),
  );
  if (owResp.statusCode != 200) {
    throw Exception('JHE could not create the OW user (${owResp.statusCode}): ${owResp.body}');
  }
  final ow = jsonDecode(owResp.body) as Map<String, dynamic>;
  final owUserId = _pick(ow, ['ow_user_id', 'owUserId']);
  final access = _pick(ow, ['ow_access_token', 'owAccessToken']);
  final refresh = _pick(ow, ['ow_refresh_token', 'owRefreshToken']);
  final endpoint = _pick(ow, ['ow_token_endpoint', 'owTokenEndpoint']);
  if (owUserId == null || access == null || refresh == null || endpoint == null) {
    throw Exception('JHE returned no OW tokens (check ow.app_id and ow.app_secret); keys: ${ow.keys.toList()}');
  }
  // The OW host is the token endpoint without its path.
  final owApiUrl = (endpoint as String).replaceAll(RegExp(r'/api/v1/token/refresh$'), '');
  return JheConnection(owApiUrl, owUserId as String, access as String, refresh as String);
}