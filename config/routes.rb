Devise::Oauth2Providable::Engine.routes.draw do
  root :to => "authorizations#new"

  resources :authorizations, :only => :create

  match 'authorize' => 'authorizations#new',:via=>:get
  match 'login_approval' => 'authorizations#login_approval',:via=>:get
  match 'me'=>'authorizations#me',:via=>:get
  resource :token, :only => :create
  
end
