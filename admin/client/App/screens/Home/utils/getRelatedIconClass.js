/**
 * Gets a related icon for a string, returned as a classname to be applied to a span. If no related
 * icon is found, returns a classname for a dot icon
 *
 * @param  [String] string
 * @return [String]        The classname of the icon
 */
 export default function getRelatedIconClass (string) {
	const icons = [
		{ icon: 'book', sections: ['books', 'posts', 'blog', 'blog-posts', 'stories', 'news-stories', 'content', 'siteContent'] },
		{ icon: 'briefcase', sections: ['businesses', 'companies', 'listings', 'organizations', 'partners', 'event', 'jobs'] },
		{ icon: 'calendar', sections: ['events', 'dates', 'jobsAndEvents'] },
		{ icon: 'clock', sections: ['classes', 'hours', 'times'] },
		{ icon: 'file-media', sections: ['gallery', 'galleries', 'images', 'photos', 'pictures'] },
		{ icon: 'file-text', sections: ['attachments', 'docs', 'documents', 'files'] },
		{ icon: 'location', sections: ['locations', 'markers', 'places'] },
		{ icon: 'mail', sections: ['emails', 'enquiries', 'emailMarketing'] },
		{ icon: 'megaphone', sections: ['broadcasts', 'talks', 'contactForm'] },
		{ icon: 'organization', sections: ['contacts', 'customers', 'groups', 'members', 'people', 'speakers', 'teams', 'users', 'admin', 'userManagement', 'candidates', 'employer'] },
		{ icon: 'tools', sections: ['boxes', 'items', 'packages', 'parcels', 'system'] },
		{ icon: 'tag', sections: ['tags'] },
	];
	const classes = icons
		.filter(obj => obj.sections.indexOf(string) !== -1)
		.map(obj => `octicon octicon-${obj.icon}`);

	if (!classes.length) {
		classes.push('octicon octicon-primitive-dot');
	}

	return classes.join(' ');
}
