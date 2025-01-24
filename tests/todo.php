<?php


function fn_mail($t) {
	mail($t,"body");
}
function fn_req() {
	return $_REQUEST["to"];
}
function fn_spam1($x) {
	fn_mail($x);
}
function fn_spam2() {
	fn_mail( fn_req() );
}

/* TODO:
Finds mail to external address with:

fn_spam2();			(correct)
fn_spam1( $_REQUEST["to"] );	(correct)
fn_spam1( "to" );		(incorrect!)
*/

fn_spam1( "to" );
