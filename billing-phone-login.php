<?php
/*
Plugin Name: Billing phone login
Plugin URI: 
Description: Позволяет авторизироваться при помощи платёжного номера телефона клиента WooCommerce (billing_phone)
Version: 1.0
Author: NikolayS93
Author URI: https://vk.com/nikolays_93
Author EMAIL: nikolayS93@ya.ru
License: GNU General Public License v2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
*/

/**
 * @todo:  sanitize phone number
 */
add_filter('sanitize_number', 'sanitize_text_field', 5, 1);
// add_filter('sanitize_number', 'plain_number_filter', 10, 1);
// function plain_number_filter($phonenumber){
//   $plain_number = preg_replace("/^\+7/", "8", $phonenumber);
//   $plain_number = preg_replace("/[a-z\W]/ui", "", $plain_number);

//   return $plain_number;
// }

// add_action('woocommerce_checkout_process', 'is_phone');
// function is_phone() {
//   $billing_phone = sanitize_text_field( $_POST['billing_phone'] );
//   // your function's body above, and if error, call this wc_add_notice
//   // wc_add_notice( __( 'Your phone number is wrong.' ), 'error' );
// }

/**
 * Authenticates a user using the woocommerce billing phone number and password.
 *
 * @since 4.5.0
 *
 * @based on wp_authenticate_email_password from wp-includes/user.php.
 * @param WP_User|WP_Error|null $user     WP_User or WP_Error object if a previous
 *                                        callback failed authentication.
 * @param string                $phone    Phone number for authentication.
 * @param string                $password Password for authentication.
 * @return WP_User|WP_Error WP_User on success, WP_Error on failure.
 */
add_filter( 'authenticate', 'wp_authenticate_phone_password', 25, 3 );
function wp_authenticate_phone_password( $user, $phone, $password ) {
  if ( $user instanceof WP_User ) {
    return $user;
  }

  $phonenumber = apply_filters( 'sanitize_number', $phone );

  /** Check empty fields */
  if ( empty( $phonenumber ) || empty( $password ) ) {
    if ( is_wp_error( $user ) ) {
      return $user;
    }

    $error = new WP_Error();

    if ( empty( $phonenumber ) ) {
      $error->add( 'empty_username', __( '<strong>ERROR</strong>: The phone number field is empty.' ) ); // Uses 'empty_username' for back-compat with wp_signon()
    }

    if ( empty( $password ) ) {
      $error->add( 'empty_password', __( '<strong>ERROR</strong>: The password field is empty.' ) );
    }

    return $error;
  }

  $users = get_users(array('meta_key' => 'billing_phone', 'meta_value' => $phonenumber));
  /** first finded user */
  $user = reset( $users );

  if ( ! $user ) {
    return new WP_Error( 'invalid_email',
      __( '<strong>ERROR</strong>: Invalid email or phone number.' ) .
      ' <a href="' . wp_lostpassword_url() . '">' .
      __( 'Lost your password?' ) .
      '</a>'
    );
  }

  /** This filter is documented in wp-includes/user.php */
  $user = apply_filters( 'wp_authenticate_user', $user, $password );

  if ( is_wp_error( $user ) ) {
    return $user;
  }

  if ( ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
    return new WP_Error( 'incorrect_password',
      sprintf(
        /* translators: %s: phone number */
        __( '<strong>ERROR</strong>: The password you entered for the phone number or email address %s is incorrect.' ),
        '<strong>' . $phonenumber . '</strong>'
      ) .
      ' <a href="' . wp_lostpassword_url() . '">' .
      __( 'Lost your password?' ) .
      '</a>'
    );
  }

  return $user;
}