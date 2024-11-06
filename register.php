<?php
session_start(); // Start a session to store messages
//include('config.php'); // Connecting to a DB

function get_db_connection()
{
    $dbHost = "MySQL-8.2";
    $dbUsername = "root";
    $dbPassword = "";
    $dbName = "marlin";

    try {
        $pdo = new PDO("mysql:host=$dbHost;dbname=$dbName;charset=utf8", $dbUsername, $dbPassword);
        // Устанавливаем режим обработки ошибок
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        die("Connection failed: " . $e->getMessage());  //echo "Connection error: " . htmlspecialchars($e->getMessage());
//        return null; // in case of error
    }
}


function get_user_by_email($email)
{
    /*
     * Parameters:
            string - $email
     * Description: search user by email
     *   Return value: array
     */

    $pdo = get_db_connection();
    if (!$pdo) {
        return []; // Return an empty array in case of connection error
    }
    $sql = "SELECT * FROM users WHERE email = :email LIMIT 1";
    $stmt = $pdo->prepare($sql);

    // Bind the parameter and execute the request
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
    $stmt->execute();

    // Result
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
}


function add_user($email, $password, $confirm_password)
{
    /*
    Parameters:
            string - $email
            string - $password
            string - $confirm_password
    Description: add user to database if passwords match
    Return value: int (user_id) or string (error message)
    */

    // Check if the user already exists
    if (get_user_by_email($email)) {
        return "User with this email already exists.";
    }

    // Check if the passwords match
    if ($password !== $confirm_password) {
        return "Passwords do not match.";
    }

    $pdo = get_db_connection();
    if (!$pdo) {
        return "Database connect error.";
    }

    // Prepare the SQL statement
    $sql = "INSERT INTO users (email, password) VALUES(:email, :password)";
    $stmt = $pdo->prepare($sql);

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Bind parameters
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password', $hashed_password);

    // Execute the statement
    if ($stmt->execute()) {
        echo "User added successfully!";
        // Get the ID of the newly inserted user
        $user_id = $pdo->lastInsertId();
    } else {
        return "Error adding user.";
    }
    return $user_id;
}

//add_user('kuzma@soap.clean', 'qweqwe', 'qweqwe');

//function set_flash_message($name, $message)
//{
//    /*
//     * Parameters:
//     *          string - $name (key)
//     *          string - $message (value, text of message)
//     *
//     * Description: prepare a flash message
//     * Return value: null
//     */
//
//    $_SESSION[$name] = $message;
//}
//
//
//function display_flash_message($name)
//{
//    /*
//     * Parameters: string - $name (key)
//
//     * Description: Display flash message
//     * Return value: null
//     */
//
//    if (isset($_SESSION[$name])) {
//        echo '<div class="item item_2">' . $_SESSION[$name] . '</div>';
//        unset($_SESSION[$name]);    // Remove message after displaying it
//    }
//}
//
//
//function redirect_to($path)
//{
//    /*
//     * Parameters: string - $path
//     *
//     * Description: redirect to another page
//     *
//     * Return value: null
//     */
//    if (!empty($path)) {
//        // Setting an HTTP header for redirection
//        header("Location: " . $path);
//
//        // End script execution after redirection
//        exit();
//    } else {
//        // In case of empty path you can handle the error or display a message
//        echo "Error: Redirect path cannot be empty";
//    }
//}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Getting data from the form
    $email = $_POST['email'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if (empty($email) || empty($password) || empty($confirm_password)) {
        die("Please, fill in all fields.");
    }

    // Calling the add user function
    $result = add_user($email, $password, $confirm_password);


//    // Store result in session variable
//    set_flash_message('registration_message', htmlspecialchars($result));

    // Redirect back to the registration page
    redirect_to("register.php");

} else {
    echo "Invalid request method";
}

?>