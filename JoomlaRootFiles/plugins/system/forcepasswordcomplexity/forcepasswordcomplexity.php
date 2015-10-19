<?php
/**
 * @Copyright
 * @package    FPC - Force Password Complexity for Joomla! 3.x
 * @author     Viktor Vogel <admin@kubik-rubik.de>
 * @version    3.1.0 - 2015-08-01
 * @link       https://joomla-extensions.kubik-rubik.de/fpc-force-password-complexity
 *
 * @license    GNU/GPL
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
defined('_JEXEC') or die('Restricted access');

class PlgSystemForcePasswordComplexity extends JPlugin
{
    function __construct(&$subject, $config)
    {
        parent::__construct($subject, $config);
        $this->loadLanguage('plg_system_forcepasswordcomplexity', JPATH_ADMINISTRATOR);
    }

    public function onUserBeforeSave($user, $isnew, $new)
    {
        // Is it a password change procedure? If not, do not execute the plugin
        if(empty($new['password_clear']))
        {
            return true;
        }

        // Check execution location
        $execution = (int)$this->params->get('execution', 0);

        if(!empty($execution))
        {
            $app = JFactory::getApplication();

            if(($execution == 1 AND $app->isAdmin()) OR ($execution == 2 AND $app->isSite()))
            {
                return true;
            }
        }

        // Check user state
        $all_users = (int)$this->params->get('all_users', 1);

        if(($all_users == 2 AND empty($isnew)) OR ($all_users == 3 AND !empty($isnew)))
        {
            return true;
        }

        // Check user group
        $restrict_usergroups = (int)$this->params->get('restrict_usergroups', 0);
        $output_warning = false;
        $output_warning_array = array();

        if(!empty($restrict_usergroups))
        {
            $user_restricted = false;
            $restricted_usergroups = array_map('intval', (array)$this->params->get('restricted_usergroups'));

            foreach($restricted_usergroups as $restricted_usergroup)
            {
                if(in_array($restricted_usergroup, $user['groups']))
                {
                    $user_restricted = true;
                    break;
                }
            }

            if($restrict_usergroups == 1)
            {
                if($user_restricted == false)
                {
                    $output_warning = true;
                }
            }
            elseif($restrict_usergroups == 2)
            {
                if($user_restricted == false)
                {
                    return true;
                }
            }
        }

        // Length of password
        $length = (int)$this->params->get('length', 8);
        $length_input = strlen($new['password_clear']);

        if($length > $length_input)
        {
            if(empty($output_warning))
            {
                throw new Exception(JText::sprintf('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_LENGTH', $length));
            }
            else
            {
                $output_warning_array[] = JText::sprintf('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_LENGTH_WARNING', $length);
            }
        }

        // Name in the password
        $no_name = (int)$this->params->get('no_name', 1);

        if(!empty($no_name))
        {
            if(stripos($new['password_clear'], $new['username']) !== false OR stripos($new['password_clear'], $new['name']) !== false)
            {
                if(empty($output_warning))
                {
                    throw new Exception(JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_NAME'));
                }
                else
                {
                    $output_warning_array[] = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_NAME_WARNING');
                }
            }
        }

        // Email address in the password
        $no_email = (int)$this->params->get('no_email', 1);

        if(!empty($no_email))
        {
            $email_input = explode('@', $new['email']);

            if(stripos($new['password_clear'], $email_input[0]) !== false OR stripos($new['password_clear'], str_replace(strrchr($email_input[1], '.'), '', $email_input[1])) !== false)
            {
                if(empty($output_warning))
                {
                    throw new Exception(JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_EMAIL'));
                }
                else
                {
                    $output_warning_array[] = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_EMAIL_WARNING');
                }
            }
        }

        // Entropy of password
        $entropy = (float)$this->params->get('entropy', 2);
        $entropy_input = (float)$this->entropy($new['password_clear'], $length_input);

        if($entropy > $entropy_input)
        {
            if(empty($output_warning))
            {
                throw new Exception(JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_ENTROPY'));
            }
            else
            {
                $output_warning_array[] = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_ENTROPY_WARNING');
            }
        }

        // Qunatity per character
        $quantity_per_character = (int)$this->params->get('quantity_per_character', 2);

        if(!empty($quantity_per_character))
        {
            $quantity_per_character_input = $this->quantityPerCharacter($new['password_clear'], $quantity_per_character);

            if(empty($quantity_per_character_input))
            {
                if(empty($output_warning))
                {
                    throw new Exception(JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_QUANTITY'));
                }
                else
                {
                    $output_warning_array[] = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_QUANTITY_WARNING');
                }
            }
        }

        // Consecutive same characters
        $consecutive_characters = (int)$this->params->get('consecutive_characters', 1);

        if(!empty($consecutive_characters))
        {
            $consecutive_characters_input = $this->consecutiveSameCharacters($new['password_clear'], $consecutive_characters);

            if(empty($consecutive_characters_input))
            {
                if(empty($output_warning))
                {
                    throw new Exception(JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_CONSECUTIVE'));
                }
                else
                {
                    $output_warning_array[] = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_CONSECUTIVE_WARNING');
                }
            }
        }

        // Check specified types
        $types = (array)$this->params->get('types');

        if(!empty($types))
        {
            $error_type = false;
            $types_input = $this->checkCharacterTypes($new['password_clear'], $types, $error_type);

            if(empty($types_input))
            {
                $types_array = array();

                foreach($types as $type)
                {
                    $types_array[] = $this->errorTypesOutput($type);
                }

                $types_required = implode(', ', $types_array);

                if(empty($output_warning))
                {
                    throw new Exception(JText::sprintf('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_TYPE', $types_required));
                }
                else
                {
                    $output_warning_array[] = JText::sprintf('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_TYPE_WARNING', $types_required);
                }
            }
        }

        if(!empty($output_warning_array))
        {
            $output_warning = implode('<br />', $output_warning_array);
            JFactory::getApplication()->enqueueMessage(JText::sprintf('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_WARNING', $output_warning));
        }

        return true;
    }

    /**
     * Calculates the entropy of the entered password in Bits
     * See: http://stackoverflow.com/questions/3198005/help-with-the-calculation-and-usefulness-of-password-entropy and http://codepad.org/OvvRKwQj
     *
     * @param string $password
     * @param int    $length
     *
     * @return float
     */
    private function entropy($password, $length)
    {
        $h = 0;

        foreach(count_chars($password, 1) as $v)
        {
            $p = $v / $length;
            $h -= $p * log($p) / log(2);
        }

        return number_format($h / 1.44, 2, '.', '');
    }

    /**
     * Checks the quantity per character of the entered password
     *
     * @param string $password
     * @param int    $quantity_per_character
     *
     * @return boolean
     */
    private function quantityPerCharacter($password, $quantity_per_character)
    {
        foreach(count_chars($password, 1) as $value)
        {
            if($value > $quantity_per_character)
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks the quantity of consecutive same characters of the entered password
     *
     * @param string $password
     * @param int    $consecutive_characters
     *
     * @return boolean
     */
    private function consecutiveSameCharacters($password, $consecutive_characters)
    {
        return !preg_match('@(.)\1{'.$consecutive_characters.'}@', $password);
    }

    /**
     * Checks the entered character types of the password
     *
     * @param string $password
     * @param array  $types
     * @param string $error_type
     *
     * @return bool
     */
    private function checkCharacterTypes($password, $types, &$error_type)
    {
        foreach($types as $type)
        {
            if($type != 'special')
            {
                if(!preg_match('@['.$type.']@', $password))
                {
                    $error_type = $type;

                    return false;
                }
            }
            else
            {
                if(!preg_match('@[^0-9a-zA-Z]@', $password))
                {
                    $error_type = $type;

                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Returns the translation of the error type
     *
     * @param string $type
     *
     * @return string
     */
    private function errorTypesOutput($type)
    {
        if($type == 'A-Z')
        {
            $type_replacement = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_TYPE_UPPERCASELETTER');
        }
        elseif($type == 'a-z')
        {
            $type_replacement = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_TYPE_LOWERCASELETTER');
        }
        elseif($type == '0-9')
        {
            $type_replacement = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_TYPE_NUMBER');
        }
        elseif($type == 'special')
        {
            $type_replacement = JText::_('PLG_FORCEPASSWORDCOMPLEXITY_ERROR_TYPE_SPECIALCHARACTER');
        }

        return $type_replacement;
    }
}
