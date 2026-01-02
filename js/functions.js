/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2025 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDTool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/**
 * Audit Plugin JavaScript Functions
 * 
 * This file contains all JavaScript functions for the Audit plugin
 */

/**
 * Apply filter to audit log
 */
function audit_applyFilter() {
	strURL = 'audit.php' +
		'?filter='+$('#filter').val()+
		'&rows='+$('#rows').val()+
		'&page='+$('#page').val()+
		'&event_page='+$('#event_page').val()+
		'&user_id='+$('#user_id').val()+
		'&header=false';
	loadPageNoHeader(strURL);
}

/**
 * Clear all filters
 */
function audit_clearFilter() {
	strURL = 'audit.php?clear=1&header=false';
	loadPageNoHeader(strURL);
}

/**
 * Global variable to store audit timer
 */
var auditTimer = null;

/**
 * Open dialog to display audit event details
 * @param {number} id - The audit event ID
 */
function audit_open_dialog(id) {
	$.get('audit.php?action=getdata&id='+id, function(data) {
		var width;
		if (data.indexOf('narrow') > 0) {
			width = 400;
		} else {
			width = 700;
		}
		$('body').append('<div id="audit" style="display:block;display:none;" title="Audit Event Details">'+data+'</div>');
		$('#audit').dialog({
			minWidth: width,
			position: {
				my: 'left',
				at: 'right',
				of: $('span[id="event'+id+'"]')
			}
		});
	});
}

/**
 * Close audit dialog
 */
function audit_close_dialog() {
	if ($('#audit').length) {
		if (typeof $('#audit').dialog() === 'function') {
			$('#audit').dialog('close');
		}
		$('#audit').remove();
	}
}

/**
 * Initialize audit event handlers on document ready
 */
$(function() {
	// Filter change event handlers
	$('#event_page, #user_id, #rows').change(function() {
		audit_applyFilter();
	});

	$('#refresh').click(function() {
		audit_applyFilter();
	});

	$('#clear').click(function() {
		audit_clearFilter();
	});

	$('#purge').click(function() {
		strURL = 'audit.php?action=purge&header=false';
		loadPageNoHeader(strURL);
	});

	$('#export').click(function() {
		document.location = 'audit.php?action=export' +
			'&filter='+$('#filter').val()+
			'&event_page='+$('#event_page').val()+
			'&user_id='+$('#user_id').val();
	});

	$('#form_audit').submit(function(event) {
		event.preventDefault();
		audit_applyFilter();
	});

	// Hover event handlers for audit event details
	$('span[id^="event"]').hover(function() {
		audit_close_dialog();

		id = $(this).attr('id').replace('event', '');

		if (auditTimer != null) {
			clearTimeout(auditTimer);
		}

		auditTimer = setTimeout(function() { audit_open_dialog(id); }, 400);
	},
	function() {
		if (auditTimer != null) {
			clearTimeout(auditTimer);
		}

		$('#dialog').hover(function() {
			clearTimeout(auditTimer);
		}, function() {
			auditTimer = setTimeout(function() { audit_close_dialog(); }, 400);
		});
	});
});
