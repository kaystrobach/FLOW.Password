# FLOW.Password

Password Validation Package for version 3.x of the `neos/flow` framework.
Update for flow 4.x is planned.

## Inclusion in Template

The Validator requires 2 fields, which are named like the controller parameter appended with `[0]` and `[1]`. 

```
	<div class="form-group">
		<label for="newPassword" class="col-sm-4 control-label">neues Passwort</label>
		<div class="col-sm-4">
			<div class="input-group passwordfield">
				<f:form.password  id="newPassword" name="newPassword[0]" class="form-control"  />
				<span class="input-group-addon passwordDisplayArea" style="display: none;" data-behaviour="clipboard"></span>
				<span class="input-group-btn">
					<button class="btn btn-default" type="button" title="Passwort generieren">
						<span class="glyphicon glyphicon-random"></span>
					</button>
				</span>
			</div>
		</div>
	</div>
	<div class="form-group">
		<label for="newPasswordDuplicate" class="col-sm-4 control-label">neues Passwort bestätigen</label>
		<div class="col-sm-4">
			<f:form.password name="newPassword[1]" class="form-control passwordfield-duplicate" id="newPasswordDuplicate" />
			<p class="help-block">
				Wird nur gespeichert, wenn beide gleich sind und mindestens 6 Zeichen lang.
			</p>
		</div>
	</div>
```

## Controller

Build an action controller and add an action to change the password.

```
	/**
	 * @Flow\Inject()
	 * @var HashService
	 */
	protected $hashService;
	
	/**
     * @Flow\Inject()
     * @var AccountRepository
     */
    protected $accountRepository;

	/**
	 * @param array $newPassword
	 * @throws StopActionException
     *
     * @Flow\Validate(argumentName="newPassword", type="KayStrobach\Password\Validation\Validator\PasswordValidator", options={"minimumChars":6, "accountIdentifierNotContained":1, "partyNameNotContained":1})
	 */
	public function changePasswordAction($newPassword) {

	    $account->setCredentialsSource($this->hashService->hashPassword($plainPassword, 'default'));
        if($this->persistenceManager->isNewObject($account)) {
            $this->accountRepository->add($account);
        } else {
            $this->accountRepository->update($account);
        }

		$this->addFlashMessage('Password changed');
		$this->redirect('index');
	}
```