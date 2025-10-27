from odoo import models, fields, api
from datetime import datetime, timedelta, timezone

class JwtRefreshToken(models.Model):
    _name = "jwt.refresh.token"
    _description = "JWT Refresh Token"
    _rec_name = "user_id"
    _order = "create_date desc"

    user_id = fields.Many2one("res.users", required=True, index=True, ondelete="cascade")
    token_hash = fields.Char(required=True, index=True)  # sha256 hex
    expires_at = fields.Datetime(required=True, index=True)
    revoked = fields.Boolean(default=False, index=True)
    rotated_from_id = fields.Many2one("jwt.refresh.token", index=True)
    user_agent = fields.Char()
    ip_address = fields.Char()

    @api.model
    def create_token(self, user, token_hash, ttl_days, ua=None, ip=None, rotated_from=None):
        now = datetime.now()
        rec = self.sudo().create({
            "user_id": user.id,
            "token_hash": token_hash,
            "expires_at": now + timedelta(days=ttl_days),
            "user_agent": ua or "",
            "ip_address": ip or "",
            "rotated_from_id": rotated_from.id if rotated_from else False,
        })
        return rec

    def revoke(self):
        self.sudo().write({"revoked": True})

    @api.model
    def revoke_all_for_user(self, user_id):
        self.sudo().search([("user_id", "=", user_id), ("revoked", "=", False)]).write({"revoked": True})
