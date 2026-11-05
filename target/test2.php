<?php

// -----------------------------
// Cookie Deserialization
// -----------------------------
if (isset($_COOKIE['data'])) {
    $obj = unserialize($_COOKIE['data']);
}

// -----------------------------
// Command Injection
// -----------------------------
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}

// -----------------------------
// File Inclusion
// -----------------------------
if (isset($_GET['page'])) {
    include($_GET['page']);
}

// -----------------------------
// SQL Injection
// -----------------------------
$conn = mysqli_connect("localhost", "root", "", "test");

if (isset($_POST['user'])) {
    $user = $_POST['user'];
    $pass = $_POST['pass'];

    $query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $res = mysqli_query($conn, $query);

    if (mysqli_fetch_assoc($res)) {
        echo "Login success";
    } else {
        echo "Fail";
    }
}

// -----------------------------
// Debug Info Leak
// -----------------------------
phpinfo();

?>
