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
    
File: `C:\basil\source_code\drupal\core\includes\bootstrap.inc`

    /**
     * Checks whether a string is valid UTF-8.
     *
     * All functions designed to filter input should use drupal_validate_utf8
     * to ensure they operate on valid UTF-8 strings to prevent bypass of the
     * filter.
     *
     * When text containing an invalid UTF-8 lead byte (0xC0 - 0xFF) is presented
     * as UTF-8 to Internet Explorer 6, the program may misinterpret subsequent
     * bytes. When these subsequent bytes are HTML control characters such as
     * quotes or angle brackets, parts of the text that were deemed safe by filters
     * end up in locations that are potentially unsafe; An onerror attribute that
     * is outside of a tag, and thus deemed safe by a filter, can be interpreted
     * by the browser as if it were inside the tag.
     *
     * The function does not return FALSE for strings containing character codes
     * above U+10FFFF, even though these are prohibited by RFC 3629.
     *
     * @param $text
     *   The text to check.
     *
     * @return bool
     *   TRUE if the text is valid UTF-8, FALSE if not.
     *
     * @see \Drupal\Component\Utility\Unicode::validateUtf8()
     *
     * @deprecated in Drupal 8.0.0, will be removed before Drupal 9.0.0.
     *   Use \Drupal\Component\Utility\Unicode::validateUtf8().
     *
     * @see https://www.drupal.org/node/1992584
     */
    function drupal_validate_utf8($text) {
      return Unicode::validateUtf8($text);
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
      
Even preg_match has its own problems and could not be trusted completely:
https://stackoverflow.com/questions/1725227/preg-match-and-utf-8-in-php

The unit tests for Drupal on validating UTF-8 are very weak, see the `testValidateUtf8(` function.

PHP Unicode Dont Play Nicely
https://jonnybarnes.uk/blog/2013/06/getting-php-to-play-nicely-with-unicode

Important
https://blog.because-security.com/t/drupal-drupalrequestsanitizer-fixes-pre-auth-remote-code-exec-bug-sa-core-2018-002-cve-2018-7600/313

Medium
https://api.drupal.org/api/drupal/includes%21bootstrap.inc/function/drupal_validate_utf8/7.x

https://www.drupal.org/node/1992584

https://stackoverflow.com/questions/1282986/utf-8-validation-in-php-without-using-preg-match

https://stackoverflow.com/questions/279170/utf-8-all-the-way-through

