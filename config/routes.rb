Devise::Oauth2Providable::Engine.routes.draw do
  root :to => "authorizations#new"

  resources :authorizations, :only => :create

  match 'authorize' => 'authorizations#new'
  match 'login_approval' => 'authorizations#login_approval'
  match 'me'=>'authorizations#me'
  resource :token, :only => :create
  
end
