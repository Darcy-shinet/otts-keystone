var utils = require('keystone-utils');
var session = require('../../../../lib/session');
var fs = require('fs');
var request = require('request');

async function signin(req, res) {
	var keystone = req.keystone;
	if (!keystone.security.csrf.validate(req)) {
		return res.apiError(403, 'invalid csrf');
	}
	if (!req.body.email || !req.body.password) {
		return res.status(401).json({ error: 'email and password required' });
	}
	if (!req.body.recaptchatToken && process.env.ADMIN_LOGIN_GOOGLE_RECAPTCHA === 'true') {
		return res.status(401).json({ error: 'Login is abnormal, please try again later.' });
	}
	try {
		if(process.env.ADMIN_LOGIN_GOOGLE_RECAPTCHA === 'true') {
			let res = await getGoogleCaptcha(req.body.recaptchatToken);
			res = JSON.parse(res);
			if(!res || res.success === false || res.score < 0.4){
				return res.status(401).json({ error: 'Login is abnormal, please try again later.' });
			}
		}
	} catch (error) {
		return res.status(401).json({ error: 'Login is abnormal, please try again later.' });
	}
	var User = keystone.list(keystone.get('user model'));
	var emailRegExp = new RegExp('^' + utils.escapeRegExp(req.body.email) + '$', 'i');
	User.model.findOne({ email: emailRegExp }).exec(function (err, user) {
		if (user) {
			keystone.callHook(user, 'pre:signin', req, function (err) {
				if (err) return res.status(500).json({ error: 'pre:signin error', detail: err });
				user._.password.compare(req.body.password, function (err, isMatch) {
					if (isMatch) {
						/* save logs */
						saveLogs(req, user);

						session.signinWithUser(user, req, res, function () {
							keystone.callHook(user, 'post:signin', req, function (err) {
								if (err) return res.status(500).json({ error: 'post:signin error', detail: err });
								res.json({ success: true, user: user });
							});
						});
					} else if (err) {
						return res.status(500).json({ error: 'bcrypt error', detail: err });
					} else {
						return res.status(401).json({ error: 'invalid details' });
					}
				});
			});
		} else if (err) {
			return res.status(500).json({ error: 'database error', detail: err });
		} else {
			return res.status(401).json({ error: 'invalid details' });
		}
	});
}

function getGoogleCaptcha(captchaToken) {
	return new Promise(function (resolve, reject) {
		request({
			url: 'https://www.google.com/recaptcha/api/siteverify',
			method: 'POST',
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: `secret=6LdGkLEUAAAAAObrkagqK-MzET14aQLXF_FYq3VJ&response=${captchaToken}`,
		}, (error, res, body) => {
			if (error) {
				reject(error)
			} else {
				resolve(body)
			}
		})
	})

}

function saveLogs(req, user) {
	ip = req.headers['x-real-ip'] ||
		req.headers['x-forwarded-for'] ||
		req.socket.remoteAddress || '';
	if (ip.split(',').length > 0) {
		ip = ip.split(',')[0];
	}
	let agent = req.headers['user-agent'];
	let userId = user._id;
	let params = {
		userName: userId,
		loginIp: ip,
		loginRemark: agent,
	};
	keystone.list('LoginLogs').model(params).save((err, result) => {
	})
	return;
}

module.exports = signin;
