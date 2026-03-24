from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/predict")
async def predict(url: str):
    # Implementation for prediction will go here
    pass