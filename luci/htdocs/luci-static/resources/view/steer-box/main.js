'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require uci';

var callStatus = rpc.declare({ object: 'steer-box', method: 'status' });
var callReleases = rpc.declare({ object: 'steer-box', method: 'releases' });
var callInstall = rpc.declare({ object: 'steer-box', method: 'install', params: ['version', 'packages'] });

var NAMES = {
	'steer-core': _('Движок'),
	'steer-vless': 'VLESS',
	'steer-hysteria2': 'Hysteria2',
	'steer-proxy': 'Trojan, Shadowsocks, SOCKS, HTTP, VMess',
	'steer-xsteer': 'xsteer',
	'steer-obfs': _('Обфускатор WireGuard')
};

function packagesTable(st) {
	var rows = (st.packages || []).map(function(p) {
		var state;
		if (p.installed)
			state = E('span', { 'style': 'color:var(--success-color-high, #2e7d32)' }, p.installed);
		else if (p.needed)
			state = E('strong', { 'style': 'color:var(--error-color-high, #c62828)' }, _('нужен, не установлен'));
		else
			state = E('span', { 'style': 'opacity:.6' }, _('не установлен'));
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, NAMES[p.name] || p.name),
			E('td', { 'class': 'td' }, E('code', {}, p.name)),
			E('td', { 'class': 'td' }, state),
			E('td', { 'class': 'td' }, p.needed ? _('нужен') : '')
		]);
	});
	return E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Пакет')),
			E('th', { 'class': 'th' }, ''),
			E('th', { 'class': 'th' }, _('Версия')),
			E('th', { 'class': 'th' }, _('Текущему конфигу'))
		])
	].concat(rows));
}

/* Версии steer, с которыми коннектор работает: не старше той, с которой он собран (поле метки,
 * приоритет правил и вопрос «не пересылать» к резолверу появились в ней). */
function verGE(a, b) {
	var x = a.split('.').map(Number), y = b.split('.').map(Number);
	for (var i = 0; i < 3; i++) {
		if ((x[i] || 0) !== (y[i] || 0))
			return (x[i] || 0) > (y[i] || 0);
	}
	return true;
}

function installBlock(st, rel) {
	var min = st.steer_min || '0.0.0';
	var versions = ((rel && rel.versions) || []).filter(function(v) { return verGE(v, min); });
	var sel = E('select', { 'class': 'cbi-input-select' }, versions.map(function(v) {
		return E('option', { 'value': v }, v);
	}));
	var onlyNeeded = E('input', { 'type': 'checkbox', 'checked': true });
	var btn = E('button', {
		'class': 'btn cbi-button cbi-button-apply',
		'disabled': versions.length ? null : true,
		'click': ui.createHandlerFn(this, function() {
			var pkgs = [];
			if (!onlyNeeded.checked)
				pkgs = (st.packages || []).filter(function(p) { return p.needed || p.installed; })
					.map(function(p) { return p.name; });
			return callInstall(sel.value, pkgs).then(function(res) {
				if (res && res.ok) {
					ui.addNotification(null, E('p', _('Установлено. Страница обновится.')), 'info');
					window.setTimeout(function() { location.reload(); }, 1500);
				} else {
					ui.addNotification(null, [
						E('p', _('Не удалось установить.')),
						E('pre', {}, (res && (res.error || res.output)) || '')
					], 'danger');
				}
			});
		})
	}, _('Установить'));
	return E('div', { 'class': 'cbi-section-node' }, [
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Версия steer')),
			E('div', { 'class': 'cbi-value-field' }, versions.length ? sel : E('em', {}, _('Выпусков steer %s и новее пока нет').format(min)))
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Только нужные пакеты')),
			E('div', { 'class': 'cbi-value-field' }, onlyNeeded)
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, ''),
			E('div', { 'class': 'cbi-value-field' }, btn)
		])
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			callStatus(),
			L.resolveDefault(callReleases(), { versions: [] }),
			uci.load('steer-box')
		]);
	},

	render: function(data) {
		var st = data[0] || {}, rel = data[1] || {};
		var m, s, o;

		m = new form.Map('steer-box', _('Steer Connector'),
			_('sing-box для podkop и forkop на движке steer.'));

		s = m.section(form.NamedSection, 'main', 'steer-box', _('Каким sing-box представляться'));
		o = s.option(form.ListValue, 'variant', _('Вариант'));
		o.value('extended', 'extended');
		o.value('stable', 'stable');
		o.default = 'extended';
		o = s.option(form.Value, 'version', _('Версия'));
		o.placeholder = '1.12.22';
		o.validate = function(id, v) {
			return (v === '' || /^\d+\.\d+\.\d+$/.test(v)) ? true : _('Версия вида 1.12.22');
		};

		s = m.section(form.NamedSection, 'main', 'steer-box', _('Настройки'));
		o = s.option(form.ListValue, 'log_level', _('Журнал'));
		o.value('', _('как в конфиге sing-box'));
		['trace', 'debug', 'info', 'warn', 'error'].forEach(function(l) { o.value(l, l); });
		o = s.option(form.Value, 'mark_mask', _('Поле метки'));
		o.placeholder = '0x000000ff';
		o.validate = function(id, v) {
			return (v === '' || /^0x[0-9a-fA-F]{1,8}$/.test(v)) ? true : _('Шестнадцатеричная маска, например 0x000000ff');
		};
		o = s.option(form.Value, 'rule_pref', _('Приоритет правил'));
		o.datatype = 'range(1,32764)';
		o.placeholder = '100';

		return m.render().then(function(node) {
			var head = E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Состояние')),
				E('div', { 'class': 'cbi-section-node' }, [
					E('div', { 'class': 'cbi-value' }, [
						E('label', { 'class': 'cbi-value-title' }, 'sing-box'),
						E('div', { 'class': 'cbi-value-field' }, [
							E('code', {}, st.sing_box || '—'), ' ',
							st.running ? E('span', {}, _('работает')) : E('span', { 'style': 'opacity:.6' }, _('не запущен'))
						])
					])
				]),
				E('h3', {}, _('Пакеты steer')),
				packagesTable(st),
				E('h3', {}, _('Установка steer')),
				installBlock(st, rel)
			]);
			var desc = node.querySelector('.cbi-map-descr');
			node.insertBefore(head, desc ? desc.nextSibling : (node.childNodes[1] || null));
			return node;
		});
	}
});
