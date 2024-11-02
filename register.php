<?php
function get_db_connection()
{
    $dbHost = "MySQL-8.2";
    $dbUsername = "root";
    $dbPassword = "";
    $dbName = "marlin";

    try {
        $pdo = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUsername, $dbPassword);
        // Устанавливаем режим обработки ошибок
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        die("Connection failed: " . $e->getMessage());  //echo "Connection error: " . htmlspecialchars($e->getMessage());
        return null; // in case of error
    }

};


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
};

var_dump(get_user_by_email("qwe@qwe.qwe"));


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

    // Check if the passwords match
    if ($password !== $confirm_password) {
        return "Passwords do not match.";
    }

    $pdo = get_db_connection();
    if (!pdo) {
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
};

$user1 = add_user("user@soap.net", "qwe123", "qwe123");
var_dump($user1);


function set_flash_message($name, $message)
{
    /*
     * Parameters:
     *          string - $name (key)
     *          string - $message (value, text of message)
     *
     * Description: prepare a flash message
     * Return value: null
     */

    $pdo = get_db_connection();
    if (!pdo) {
        return [];
    }

    // Prepare the SQL statement
    $stmt = $pdo->prepare("UPDATE users SET message = :message WHERE name = :name");

    // Bind parameters
    $stmt->bindParam(':message', $message);
    $stmt->bindParam('name', $name);

    // Execute the statement
    if ($stmt->execute()) {
        echo "Message successfully updated!";
    } else {
        echo "Failed to update message.";
    }
};

$user1 = 'Kuzma';
$message = "ЗАРЕGUN!";
set_flash_message($user1, $message);


function display_set_message($name)
{
    /*
     * Parameters: string - $name (key)

     * Description: Display flash message
     * Return value: null
     */

    $pdo = get_db_connection();
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Prepare the sql statement
    $stmt = $pdo->prepare("SELECT message FROM users WHERE name = :name");
    $stmt->bindParam(':name', $name);

    // Execute the statemen
    $stmt->execute();

    // Getting the result
    $message = $stmt->fetchColumn();

    if ($message) {
        echo htmlspecialchars($message); // Outputting a message with XSS protection
    } else {
        echo "Message not found";
    }
};


function redirect_to($path)
{
    /*
     * Parameters: string - $path
     *
     * Description: redirect to another page
     *
     * Return value: null
     */
    if (!empty($path)) {
        // Setting an HTTP header for redirection
        header("Location: " . $path);

        // End script execution after redirection
        exit();
    } else {
        // In case of empty path you can handle the error or display a message
        echo "Error: Redirect path cannot be empty";
    }
};

?>

