

from flask import Blueprint, request, jsonify

calculator = Blueprint('calculator', __name__)

@calculator.route('/api/service_calculator', methods=['POST'])
def service_calculator():
    data = request.json

    # Extract relevant information from the request data
    home_info = data.get('home_info', {})
    family_info = data.get('family_info', {})

    # Calculate the service requirements (customize this logic as needed)
    services_needed = {
        "phone_cell": "basic",
        "internet": "standard",
        "cable_tv": "premium",
        "water": "standard",
        "sewage": "standard",
        "gas": "standard",
        "electricity": "standard",
        "home_cleaning": "regular",
        "lawn_care": "monthly",
        "elderly_care": "not_needed",
        "transportation": "public",
        "homeowners_insurance": "standard",
        "auto_insurance": "basic"
    }

    return jsonify(services_needed)

@calculator.route('/api/affordability_calculator', methods=['POST'])
def affordability_calculator():
    data = request.json

    # Extract relevant information from the request data
    family_income = data.get('family_income', 0)
    family_expenses = data.get('family_expenses', 0)
    service_cost = data.get('service_cost', 0)

    # Calculate the affordability (customize this logic as needed)
    remaining_income = family_income - family_expenses
    can_afford = remaining_income >= service_cost

    return jsonify({"can_afford": can_afford})
