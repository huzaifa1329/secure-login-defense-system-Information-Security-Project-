// Using built-in fetch (Node.js 18+)

async function testLockoutLogic() {
    const baseUrl = 'http://localhost:3000';
    const email = 'test@university.edu';

    console.log('🧪 Testing Lockout Logic: 5 attempts = 30s lock, 6+ attempts = 1min lock\n');

    try {
        // Reset test account
        console.log('🔄 Resetting test account...');
        await fetch(`${baseUrl}/reset-test-account`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        // Test 1: 5 wrong attempts should lock for 30 seconds
        console.log('\n📋 Test 1: 5 wrong attempts (should lock for 30 seconds)');
        for (let i = 1; i <= 5; i++) {
            const response = await fetch(`${baseUrl}/signin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password: `wrong${i}` })
            });
            const result = await response.json();
            console.log(`   Attempt ${i}: ${result.message}`);

            if (result.locked) {
                console.log(`   ✅ Account locked on attempt ${i} (expected: 5)`);
                break;
            }
        }

        // Wait for lock to expire
        console.log('⏳ Waiting 35 seconds for lock to expire...');
        await new Promise(resolve => setTimeout(resolve, 35000));

        // Reset and test 2: 6 wrong attempts should lock for 1 minute
        console.log('\n🔄 Resetting account for Test 2...');
        await fetch(`${baseUrl}/reset-test-account`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        console.log('\n📋 Test 2: 6 wrong attempts (should lock for 1 minute)');
        for (let i = 1; i <= 6; i++) {
            const response = await fetch(`${baseUrl}/signin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password: `wrong${i}` })
            });
            const result = await response.json();
            console.log(`   Attempt ${i}: ${result.message}`);

            if (result.locked) {
                console.log(`   ✅ Account locked on attempt ${i} (expected: 6)`);
                break;
            }
        }

        // Test successful login after lock expires
        console.log('⏳ Waiting 65 seconds for 1-minute lock to expire...');
        await new Promise(resolve => setTimeout(resolve, 65000));

        console.log('\n📋 Test 3: Successful login after lock expires');
        const successResponse = await fetch(`${baseUrl}/signin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password: 'password123' })
        });
        const successResult = await successResponse.json();
        console.log(`   Login result: ${successResult.message}`);

        if (successResult.success) {
            console.log('   ✅ Successful login after lock expired');
        } else {
            console.log('   ❌ Login failed after lock should have expired');
        }

        console.log('\n🎉 Lockout logic testing completed!');

    } catch (error) {
        console.error('❌ Test failed:', error.message);
    }
}

testLockoutLogic();
