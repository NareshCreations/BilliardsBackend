const fetch = require('node-fetch');

async function testProfile() {
  try {
    // First login to get token
    const loginResponse = await fetch('http://localhost:3001/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'admin@billiards.com',
        password: 'admin123'
      })
    });

    const loginResult = await loginResponse.json();
    console.log('Login successful, testing profile...');

    // Use token to get profile
    const profileResponse = await fetch('http://localhost:3001/api/auth/profile', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${loginResult.data.token}`,
      }
    });

    const profileResult = await profileResponse.json();
    console.log('Profile Response:', JSON.stringify(profileResult, null, 2));

  } catch (error) {
    console.error('Error:', error.message);
  }
}

testProfile();
