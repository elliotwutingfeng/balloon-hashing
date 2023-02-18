require 'simplecov'
SimpleCov.start

RSpec.configure do |rspec|
  rspec.expect_with :rspec do |c|
    c.max_formatted_output_length = nil
  end
  rspec.run_all_when_everything_filtered = true
  rspec.order = 'default'
  rspec.formatter = :documentation
end
