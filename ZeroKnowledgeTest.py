from ZeroKnowledge.Zk import Zk
import json

# Setup ZK Object
zero = Zk()

# Obtain ZK Secret
secrets = zero.getSecret()

data = {
    "fruits":[
        "apple",
        "banana"
    ]
}

# Commit ZK Data
commits = zero.create(str(data))

# Solve ZK Data
trueString = zero.solve(secrets, commits)

# Convert to iterable Object
data = json.loads(trueString.replace("'","\""))
print(data['fruits'][0])
