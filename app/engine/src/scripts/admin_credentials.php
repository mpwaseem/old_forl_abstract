<?php
declare(strict_types=1);

namespace bin;

use App\Common\Admin\Administrator;
// use App\Common\Database\Primary\Administrator;
use App\Common\Admin\Credentials;
use App\Common\Exception\AppException;
use App\Common\Kernel\CLI\AbstractCLIScript;
use Comely\Database\Schema;
use Comely\Utils\Security\Passwords;

/**
 * Class admin_credentials
 * @package bin
 */
class admin_credentials extends AbstractCLIScript
{
    public const DISPLAY_HEADER = false;
    public const DISPLAY_LOADED_NAME = true;

    /**
     * @throws AppException
     * @throws \Comely\Database\Exception\DbConnectionException
     * @throws \Comely\Utils\Security\Exception\CipherException
     * @throws \Comely\Utils\Security\Exception\PRNG_Exception
     */
    public function exec(): void
    {
        // ID
        $this->inline("ID... ");
        $id = $this->flags()->get("id");
        if (!$id || !preg_match('/^[0-9]+$/', $id)) {
            throw new AppException('Invalid value for flag "id"');
        }

        $id = intval($id);
        $this->print('{yellow}' . $id . '{/}');

        // E-mail address
        $this->inline("E-mail address... ");
        $email = $this->flags()->get("email");
        if (!$email) {
            throw new AppException('Flag "email" is required');
        }

        $this->print('{cyan}' . $email . '{/}');
        $this->print("");
        $this->repeat(".", mt_rand(6, 12), 100);
        $this->print("");

        // Password
        $password = Passwords::Generate(12, 4);

        // DB
        $db = $this->app->db()->primary();
        Schema::Bind($db, 'App\Common\Database\Primary\Administrators');

        // Create Administrator Object
        $admin = new Administrator();
        $admin->id = $id;
        $admin->status = 1;
        $admin->email = $email;
        $admin->phone = null;

        $this->print(sprintf('{grey}Password:{/} {cyan}{invert} %s {/}', $password));
        $checksum = $admin->checksum()->raw();
        
        $this->print(sprintf('{grey}Checksum:{/} {b}%s{/}',$admin->checksum()->base16()->hexits()));
        $this->print(sprintf('{grey}Credentials:{/}'));

        $credentials = new Credentials($admin);
        $credentials->setPassword($password);

        $encrypted = $admin->cipher()->encrypt($credentials);
        $dbcredentials = $encrypted->raw();

        $this->print(sprintf('{grey}Credentials:{/}'));
        $this->print($encrypted->base16()->hexits());

        $date = strtotime("now");

        $saveAdminQuery = 'INSERT ' . 'INTO `%s` (`checksum`, `status`, `email`, `credentials`, `time_stamp`) ' .
                'VALUES (:checksum, :status, :email, :credentials, :time_stamp);';

            $saveAdminData = [
                "checksum" => $checksum,
                "status" => $admin->status,
                "email" => $admin->email,
                "credentials" => $dbcredentials,
                "time_stamp" => $date
            ];


            $saveAdminQuery = $db->exec(sprintf($saveAdminQuery, Administrator::TABLE), $saveAdminData);

            if ($saveAdminQuery->isSuccess(false)) {
                $this->print('{green}SUCCESS{/}');
            } else {
                $this->print('{red}FAIL{/}');
            }

    }
}