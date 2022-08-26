# frozen_string_literal: true

shared_examples 'fail' do
  it 'fails' do
    expect { subject.call }.to raise_error(%r{#{regex}})
  end
end
