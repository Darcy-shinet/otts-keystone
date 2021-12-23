module.exports = function initList (req, res, next) {
	var keystone = req.keystone;
	req.list = keystone.list(req.params.list);
	if (!req.list) {
		if (req.headers.accept === 'application/json') {
			return res.status(404).json({ error: 'invalid list path' });
		}
		req.flash('error', 'List ' + req.params.list + ' could not be found.');
		return res.redirect('/' + keystone.get('admin path'));
	}
	// next();
	if(req.user.superAdmin || req.list.options.hidden){
		next();
	} else {
		keystone.list('Role').model.findOne({_id: req.user.roles}).exec((err, result) => {
			if(result){
				if(result.permission && result.permission.length > 0 && result.permission.indexOf(req.list.path) !== -1){
					next();
				} else {
					return res.status(404).json({ error: 'insufficient permissions' });
				}
			} else {
				req.flash('error', 'insufficient permissions.');
				return res.redirect('/' + keystone.get('admin path'));
			}
		})
	}

};