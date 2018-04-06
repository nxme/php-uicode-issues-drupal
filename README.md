# php-uicode-issues-drupal
PHP &amp; Drupal Unicode Issues

Drupal Source Code
File: \Drupal\Component\Utility\Unicode

    public static function validateUtf8($text) {
      if (strlen($text) == 0) {
        return TRUE;
      }
      // With the PCRE_UTF8 modifier 'u', preg_match() fails silently on strings
      // containing invalid UTF-8 byte sequences. It does not reject character
      // codes above U+10FFFF (represented by 4 or more octets), though.
      return (preg_match('/^./us', $text) == 1);
    }
    
File: `core/lib/Drupal/Component/Utility/Xss.php`
Filters XSS attacks:

    public static function filter($string, array $html_tags = NULL) {
      if (is_null($html_tags)) {
        $html_tags = static::$htmlTags;
      }
      // Only operate on valid UTF-8 strings. This is necessary to prevent cross
      // site scripting issues on Internet Explorer 6.
      if (!Unicode::validateUtf8($string)) {
        return '';
      }

Important
https://blog.because-security.com/t/drupal-drupalrequestsanitizer-fixes-pre-auth-remote-code-exec-bug-sa-core-2018-002-cve-2018-7600/313

Medium
https://api.drupal.org/api/drupal/includes%21bootstrap.inc/function/drupal_validate_utf8/7.x
https://www.drupal.org/node/1992584
https://stackoverflow.com/questions/1282986/utf-8-validation-in-php-without-using-preg-match
