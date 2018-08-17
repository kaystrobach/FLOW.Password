<?php

namespace KayStrobach\Password\Validation\Validator;

use Neos\Flow\Error\Error;
use Neos\Flow\Validation\Exception\InvalidValidationOptionsException;
use Neos\Flow\Validation\Validator\AbstractValidator;
use TYPO3\Party\Domain\Model\AbstractParty;
use TYPO3\Party\Domain\Model\PersonName;
use TYPO3\Party\Domain\Service\PartyService;

use Neos\Flow\Annotations as Flow;


class PasswordValidator extends AbstractValidator
{
    protected $blacklistContains = [];
    protected $blacklistEquals = [];

    /**
     * @var array
     * @Flow\InjectConfiguration(path="PasswordValidator.DeniedPasswords", package="KayStrobach.Password")
     */
    protected $passwordSettings;

    /**
     * @Flow\Inject()
     * @var PartyService
     */
    protected $partyService;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Security\Authentication\AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * This contains the supported options, each being an array of:
     *
     * 0 => default value
     * 1 => description
     * 2 => type
     * 3 => required (boolean, optional)
     *
     * @var array
     */
    protected $supportedOptions = array(
        'minimumChars' => [
            6, 'use atleast this number of chars as minimum length', 'int'
        ],
        'accountIdentifierNotContained' => [
            false, 'check wether username can be in password or not', 'boolean'
        ],
        'partyNameNotContained' => [
            false, 'check wether party can be in password or not', 'boolean'
        ],
    );

    /**
     * checks if a password fullfills given needs
     *
     * @param mixed $value
     * @return void
     * @throws InvalidValidationOptionsException if invalid validation options have been specified in the constructor
     */
    protected function isValid($value)
    {
        if (!is_array($value)) {
            $this->addError('Password is not an array.', 1499068811);
        }
        if (count($value) !== 2) {
            $this->addError('Password is not an array with 2 entries.', 1499068812);
        }

        $newPassword = $value[0];
        $newPasswordDuplicate = $value[1];
        $newPasswordLowerCase = strtolower($value[0]);

        if ($newPassword !== $newPasswordDuplicate) {
            $this->addError('Password and duplicate do not match.', 1499068813);
        }
        if (strlen($newPassword) < $this->options['minimumChars']) {
            $this->addError(
                'Need atleast {0} chars as a password.',
                1499068814,
                [
                    $this->options['minimumChars']
                ]
            );
        }

        $account = $this->authenticationManager->getSecurityContext()->getAccount();
        if ($account !== null) {
            $username = $account->getAccountIdentifier();
            if ($this->options['accountIdentifierNotContained']) {
                if (strpos($newPasswordLowerCase, strtolower($username)) !== false) {
                    $this->addError('Username must not be contained in password.', 1499068815);
                }
            }
            if (($account instanceof AbstractParty) && ($this->options['partyNameNotContained'])) {
                $party = $this->partyService->getAssignedPartyOfAccount($account);
                if (method_exists($party, 'getName')) {
                    $name = $party->getName();
                    if ($name instanceof PersonName) {
                        if ((strlen($name->getFirstName()) > 3) && (strpos($newPasswordLowerCase, strtolower($name->getFirstName())))) {
                            $this->addError('Firstname must not be contained in password.', 1499068816);
                        }
                        if ((strlen($name->getLastName()) > 3) && (strpos($newPasswordLowerCase, strtolower($name->getLastName())))) {
                            $this->addError('Lastname must not be contained in password.', 1499068817);
                        }
                        if ((strlen($name->getMiddleName()) > 3) && (strpos($newPasswordLowerCase, strtolower($name->getMiddleName())))) {
                            $this->addError('Middlename must not be contained in password.', 1499068818);
                        }
                        if ((strlen($name->getAlias()) > 3) && (strpos($newPasswordLowerCase, strtolower($name->getAlias())))) {
                            $this->addError('Alias must not be contained in password.', 1499068819);
                        }
                        if ((strlen($name->getOtherName()) > 3) && (strpos($newPasswordLowerCase, strtolower($name->getOtherName())))) {
                            $this->addError('Othername must not be contained in password.', 1499068820);
                        }
                    }
                }
            }
        }

        $this->getPasswordBlacklist();
        if (in_array($newPasswordLowerCase, $this->blacklistEquals)) {
            $this->addError('The given password is a common one an not allowed', 1499068821);
        }
        foreach ($this->blacklistContains as $key) {
            if (strpos($newPasswordLowerCase, $key) !== false) {
                $this->addError(
                    'The given password contains "{0}", which is not allowed',
                    1499068822,
                    [
                        $key
                    ]);
            }
        }
    }

    /**
     * extract password blacklist from settings
     */
    protected function getPasswordBlacklist()
    {
        $this->blackListEquals = [];
        $this->blackListContains = [];

        if ((isset($this->passwordSettings['Blacklist']['Equals'])) && (is_array($this->passwordSettings['Blacklist']['Equals']))) {
            foreach ($this->passwordSettings['Blacklist']['Equals'] as $key => $value) {
                if ($value) {
                    $this->blacklistEquals[] = strtolower($key);
                }
            }
        }
        if ((isset($this->passwordSettings['Blacklist']['Contains'])) && (is_array($this->passwordSettings['Blacklist']['Contains']))) {
            foreach ($this->passwordSettings['Blacklist']['Contains'] as $key => $value) {
                if ($value) {
                    $this->blacklistContains[] = strtolower($key);
                }
            }
        }
    }
}