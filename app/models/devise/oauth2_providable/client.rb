class Devise::Oauth2Providable::Client < ActiveRecord::Base
  has_many :access_tokens
  has_many :refresh_tokens
  has_many :authorization_codes
  has_many :versions, :class_name => "Oauth2ClientVersion"

  before_validation :customer_identifier, :on => :create, :unless => :identifier?
  before_validation :init_secret, :on => :create, :unless => :secret?
  validates :website, :secret, :presence => true
  validates :name, :presence => true, :uniqueness => true
  validates :identifier, :presence => true, :uniqueness => true

  belongs_to :latest_version, :class_name => "Oauth2ClientVersion", :foreign_key => "latest_version_id"

  def file_name
      name
  end
  def file_dir
    File.realpath("#{Rails.root}/contents")+"/applications/#{id}/"
  end


  def self.find_cached_by_identifier(identifier_id)
    Rails.cache.fetch "/oauth2/client/identifier/#{identifier_id}" do
      find_by_identifier(identifier_id)
    end
  end

  def self.find_cached_by_id(client_id)
    Rails.cache.fetch "/oauth2/client/#{client_id}" do
      find_by_id(client_id)
    end
  end

  def expire_cache
    Rails.cache.delete "/oauth2/client/identifier/#{self.identifier}"
    Rails.cache.delete "/oauth2/client/#{self.id}"
  end

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
