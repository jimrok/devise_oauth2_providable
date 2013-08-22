class Devise::Oauth2Providable::Client < ActiveRecord::Base
  has_many :access_tokens
  has_many :refresh_tokens
  has_many :authorization_codes

  before_validation :customer_identifier, :on => :create, :unless => :identifier?
  before_validation :init_secret, :on => :create, :unless => :secret?
  validates :website, :secret, :presence => true
  validates :name, :presence => true, :uniqueness => true
  validates :identifier, :presence => true, :uniqueness => true

  attr_accessible :name, :identifier, :website, :redirect_uri, :version, :description, :upgrade_url, :file_name

  private

  def customer_identifier
      max_client = Devise::Oauth2Providable::Client.order("identifier+0 desc").first
      client_id = max_client.identifier.to_i if max_client
      if client_id > 1000 then
          self.identifier = "#{client_id + 1}"
      else
          self.identifier = "1001"
      end
  end

  def init_identifier
    self.identifier = Devise::Oauth2Providable.random_id
  end

  def init_secret
    self.secret = Devise::Oauth2Providable.random_id
  end

end
