var wp_scanner = Object();

wp_scanner.addHtml = function(appendTo,Html){
	        if(jQuery(appendTo).length == 0) return;
            jQuery(appendTo).append(Html);
}