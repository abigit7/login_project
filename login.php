<?php
session_start();
$servername = "localhost";
$username = "root";  // default username
$password = "";  // default password is empty
$dbname = "user_login_db";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Prepare and bind
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($password_hash);
        $stmt->fetch();

        // Verify password
        if (password_verify($password, $password_hash)) {
            $_SESSION['user'] = $email;
            echo "<script>alert('Login successful!'); window.location.href='index.html';</script>";
        } else {
            echo "<script>alert('Invalid email or password'); window.location.href='login.html';</script>";
        }
    } else {
        echo "<script>alert('Invalid email or password'); window.location.href='login.html';</script>";
    }
    
    $stmt->close();
}

$conn->close();
?>
