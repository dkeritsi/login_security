<?php
// Initialize the session
session_start();

/*New Code*/
header("refresh: 1;");
if(!isset($_SESSION['username']) || empty($_SESSION['username'])){
	header("location: login.php");
	exit;
}
else{
	$now = time();
	if ($now > $_SESSION['expire_time']){
		header("location: login.php");
		session_destory();
	}
}
/*End of New Code*/
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
    <h1>Hi! Welcome to our site: <b><?php echo htmlspecialchars($_SESSION['username']); ?></b></h1>
    <h1>You have the following remaining seconds left: <b><?php echo htmlspecialchars($_SESSION['expire_time']-$now); ?></b></h1>
    </div>
    <p><a href="logout.php" class="btn btn-danger">Sign Out of Your Account</a></p>
</body>
</html>
