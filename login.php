<?php
// Include config file
require_once 'config.php';

// Define variables and initialize with empty values
// Modified Code here. We are not using stored_password anymore, but instead it is the hashed password. We should always initialize our varables. 
//$username = $password = $stored_password = "";
$username = $password = $hashed_password = "";
$username_err = $password_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
	//Check if Username or Passwords are empty
	if(empty(trim($_POST["username"]))){
		$username_err = 'Please enter username.';
	}else{
		$username = trim($_POST["username"]);
	}

	if(empty(trim($_POST["password"]))){
		$password_err = 'Please enter password.';
	}else{
		$password = trim($_POST["password"]);
	}

    // Validate credentials
    // Prepare a select statemen
    if(empty($username_err) && empty($password_err)){
    $sql = "SELECT username, password FROM users WHERE username = ?";

    if($stmt = mysqli_prepare($link, $sql)){
        // Bind variables to the prepared statement as parameters
        mysqli_stmt_bind_param($stmt, "s", $param_username);
        // Set parameters
        $param_username = $username;

        // Attempt to execute the prepared statement
        if(mysqli_stmt_execute($stmt)){
            	// Store result
		mysqli_stmt_store_result($stmt);
		//Check if username exists and if it doesn't we want to return the following in a non-verbose fashion.
		if(mysqli_stmt_num_rows($stmt) !=1){
			$password_err = 'The username or password is incorrect.';
			$username_err = 'The username or password is incorrect.';
		}
		else
		{ 
		
		    // Bind result variables
		    // Code Change is here. This is immaterial, but we are changing the same from "stored_password" to "hashed_password". This is what is being retrieved from the database.
		    mysqli_stmt_bind_result($stmt, $username, $hashed_password);
		    mysqli_stmt_fetch($stmt);
		    //if(!strcmp($password, $stored_password)){ Modifying the code here. We want to use the function of "password_verify" instead of merely doing a comparision between strings. Essentially, we want to take the password, the first argument, hash it and in some way, compare it against the 2nd argument which is the hashed password.
		    if(password_verify($password, $hashed_password))
		    {
			    /* Password is correct, so save the username to the session */
			    /*Modified Code with Session start function(). This code will work in conjuction with what is on the Welcome Page.*/
			    session_start();
			    $_SESSION['start_time']= time();
			    $_SESSION['expire_time'] = $_SESSION['start_time'] + 60;
			    $_SESSION['username'] = $username;
			    header("location: welcome.php");
		    } 
		    else
		    {
			    // Display an error message if password is not valid
			    // New Code Check if Password is correct. If it is not, then we return in a non-verbose fashion.
			    $password_err = 'The username or password is incorrect.';
			    $username_err = 'The username or password is incorrect.';
		    }
		}
	} 
	else
	{
            echo "Oops! Something went wrong. Please try again later.";
        }
    }
      // Close statement
      mysqli_stmt_close($stmt);
    }
    // Close connection
    mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Email Address</label>
                <input type="text" name="username"class="form-control" value="<?php echo $username; ?>">
                <span class="help-block"><?php echo $username_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <input type="password" name="password" class="form-control">
                <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
        </form>
    </div>
</body>
</html>
