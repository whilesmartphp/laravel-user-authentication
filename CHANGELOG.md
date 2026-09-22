## [1.1.0] - 2026-09-22
- Sign in with Apple
- Registration can be limited to an allow list or deny list of email domains
- OAuth accounts keep the provider id, avatar and token, and the scopes asked for are configurable
- A social provider's single name field is split into a first and last name
- The OAuth callback answers on both GET and POST, since providers differ
- The SmartPings SDK is optional. Install it only if verification runs through SmartPings. Configured without it, the package says what to install

## [1.0.5] - 2026-01-10
- Set email_verified_at on registration when verification is required
- Set email_verified_at for users registered via OAuth providers

## [1.0.4] - 2025-10-15
- Add support for firebase authentication

## [1.0.3] - 2025-10-01
- Add response interception hooks
- Implement pre-registration email and phone verification
- Add response and middleware customization

## [1.0.2] - 2025-07-31
- Added config file
- Minor bug fixes
