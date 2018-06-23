<?php

namespace League\OAuth2\Client\Test\Provider;

use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Provider\GenericProvider;

class Generic extends GenericProvider
{
    public function __construct($options = array(), $collaborators = array())
    {
        // Add the required defaults for AbstractProvider
        $options += [
            'clientId'     => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri'  => 'none',
        ];

        parent::__construct($options);
    }

    protected function fetchResourceOwnerDetails(AccessTokenInterface $token)
    {
        return [
            'mock_response_uid' => 1,
            'username'          => 'testmock',
            'email'             => 'mock@example.com',
        ];
    }
}
